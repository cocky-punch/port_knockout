use hmac::KeyInit;
use hmac::{Hmac, Mac};
use port_knockout_protocol::{Profile, Request, RequestKind, Response, ResponseStatus};
use serde::Deserialize;
use sha2::Sha256;
use std::{
    error::Error,
    fs,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    time::{Duration, sleep, timeout},
};

type HmacSha256 = Hmac<Sha256>;
type ClientResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const CONFIG_PATH: &str = "client.toml";
const RESPONSE_TIMEOUT_SECONDS: u64 = 5;

#[derive(Debug, Deserialize)]
struct Config {
    server_address: SocketAddr,
    device_id: String,
    device_secret: String,
    profile: String,
    renew_interval_seconds: u64,
}

impl Config {
    fn load() -> ClientResult<Self> {
        let contents = fs::read_to_string(CONFIG_PATH)?;
        let config: Self = toml::from_str(&contents)?;

        if config.device_id.is_empty() {
            return Err("device_id must not be empty".into());
        }

        if config.renew_interval_seconds == 0 {
            return Err("renew_interval_seconds must be greater than zero".into());
        }

        let secret = hex::decode(&config.device_secret)?;

        if secret.len() < 32 {
            return Err("device_secret must contain at least 32 bytes".into());
        }

        Ok(config)
    }

    fn profile(&self) -> ClientResult<Profile> {
        match self.profile.as_str() {
            "vpn" => Ok(Profile::Vpn),
            "ssh" => Ok(Profile::Ssh),
            "admin" => Ok(Profile::Admin),
            _ => Err("profile must be vpn, ssh, or admin".into()),
        }
    }

    fn secret_bytes(&self) -> ClientResult<Vec<u8>> {
        Ok(hex::decode(&self.device_secret)?)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Open,
    EndSession,
}

impl Action {
    fn from_args() -> ClientResult<Self> {
        match std::env::args().nth(1).as_deref() {
            Some("open") | None => Ok(Self::Open),
            Some("end-session") => Ok(Self::EndSession),
            Some(other) => Err(format!("unknown action {other:?}; use open or end-session").into()),
        }
    }

    fn request_kind(self) -> RequestKind {
        match self {
            Self::Open => RequestKind::Open,
            Self::EndSession => RequestKind::EndSession,
        }
    }
}

#[tokio::main]
async fn main() -> ClientResult<()> {
    let action = Action::from_args()?;
    let config = Config::load()?;
    let profile = config.profile()?;
    let secret = config.secret_bytes()?;

    let bind_address = match config.server_address {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };

    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(config.server_address).await?;

    println!("Server: {}", config.server_address);
    println!("Device: {}", config.device_id);

    loop {
        let timestamp = current_timestamp()?;

        let mut request = Request {
            kind: action.request_kind(),
            device_id: config.device_id.clone(),
            timestamp,
            profile,
            mac: [0; 32],
        };

        request.mac = sign(&secret, &request.authentication_bytes()?)?;
        let packet = request.to_bytes()?;
        socket.send(&packet).await?;
        let mut buffer = [0_u8; 512];

        let received = timeout(
            Duration::from_secs(RESPONSE_TIMEOUT_SECONDS),
            socket.recv(&mut buffer),
        )
        .await??;

        let response = Response::from_bytes(&buffer[..received])?;
        if response.timestamp != timestamp {
            return Err("response timestamp does not match request".into());
        }

        verify_response(&response, &secret)?;
        match response.status {
            ResponseStatus::Ok => {
                println!(
                    "Server accepted request; lease: {} seconds",
                    response.lease_in_seconds
                );
            }
            ResponseStatus::Err => {
                return Err("server rejected request".into());
            }
        }

        if action == Action::EndSession {
            println!("Session ended.");
            break;
        }

        sleep(Duration::from_secs(config.renew_interval_seconds)).await;
    }

    Ok(())
}

fn current_timestamp() -> ClientResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn sign(secret: &[u8], data: &[u8]) -> ClientResult<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(data);

    let bytes = mac.finalize().into_bytes();
    let mut result = [0_u8; 32];
    result.copy_from_slice(&bytes);

    Ok(result)
}

fn verify_response(response: &Response, secret: &[u8]) -> ClientResult<()> {
    let mut mac = HmacSha256::new_from_slice(secret)?;
    mac.update(&response.authentication_bytes());

    mac.verify_slice(&response.mac)
        .map_err(|_| "invalid response HMAC".into())
}
