use std::env;
use std::net::SocketAddr;
// use std::os::unix::net::SocketAddr;
use std::net::UdpSocket;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 7 {
        return Err(
            "usage: <server-address> <device-id> <secret-hex> <open|end-session> <renew-interval-seconds>"
                .into(),
        );
    }

    let server_addr: SocketAddr = args[1].parse()?;
    let device_id = args[2].clone();
    let secret = hex::decode(&args[3])?;

    if secret.len() < 32 {
        return Err("device secret must contain at least 32 bytes".into());
    }

    let profile = parse_profile(&args[4])?;
    let kind = parse_request_kind(&args[5])?;
    let renew_interval: u64 = args[6].parse()?;

    if renew_interval == 0 {
        return Err("renew interval must be greater than zero".into());
    }

    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };

    let socket = UdpSocket::bind(bind_addr).await?;
    let mut buffer = [0u8; 2048];

    loop {
        let request = build_request(kind, device_id.clone(), profile, &secret)?;
        let expected_timestamp = request.timestamp;
        let packet = request.to_bytes()?;

        socket.send_to(&packet, server_addr).await?;
        println!("Request sent to {server_addr}");

        let (length, source_addr) =
            timeout(Duration::from_secs(5), socket.recv_from(&mut buffer)).await??;

        if source_addr != server_addr {
            return Err(format!("response came from unexpected address {source_addr}").into());
        }

        handle_response(&buffer[..length], expected_timestamp, &secret)?;

        if kind == RequestKind::EndSession {
            break;
        }

        tokio::time::sleep(Duration::from_secs(renew_interval)).await;
    }

    Ok(())
}
