use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    config::{Config, Device},
    protocol::{Request, RequestKind, Response, ResponseStatus},
};

type HmacSha256 = Hmac<Sha256>;

const MAX_TIMESTAMP_SKEW_SECONDS: u64 = 30;

pub fn handle_request(
    request: &Request,
    config: &Config,
    source_ip: IpAddr,
) -> Result<Response, AuthError> {
    let device = config
        .devices
        .iter()
        .find(|device| device.id == request.device_id)
        .ok_or(AuthError::UnknownDevice)?;

    let secret = hex::decode(&device.secret).map_err(|_| AuthError::InvalidSecret)?;

    validate_timestamp(request.timestamp)?;
    verify_request_mac(request, &secret)?;

    match request.kind {
        RequestKind::Open => {
            // firewall::mock::open(source_ip, &config.ports, config.lease_in_seconds).awai?;
            println!(
                "authenticated OPEN request from device {:?}, source IP {source_ip}",
                device.id
            );

            println!("configured ports to open: {}", config.ports.len());

            Ok(sign_response(
                ResponseStatus::Ok,
                request.timestamp,
                config.lease_in_seconds,
                &secret,
            ))
        }
        RequestKind::EndSession => {
            // firewall::mock::close(source_ip, &config.ports).awai?;
            println!(
                "authenticated END_SESSION request from device {:?}, source IP {source_ip}",
                device.id
            );

            Ok(sign_response(
                ResponseStatus::Ok,
                request.timestamp,
                0,
                &secret,
            ))
        }
    }
}

fn validate_timestamp(timestamp: u64) -> Result<(), AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::ClockError)?
        .as_secs();

    if now.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECONDS {
        return Err(AuthError::TimestampOutOfRange);
    }

    Ok(())
}

fn verify_request_mac(request: &Request, secret: &[u8]) -> Result<(), AuthError> {
    let authentication_bytes = request
        .authentication_bytes()
        .map_err(|_| AuthError::InvalidRequest)?;

    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidSecret)?;

    mac.update(&authentication_bytes);
    mac.verify_slice(&request.mac)
        .map_err(|_| AuthError::InvalidMac)
}

fn sign_response(
    status: ResponseStatus,
    timestamp: u64,
    lease_in_seconds: u32,
    secret: &[u8],
) -> Response {
    let mut response = Response {
        status,
        timestamp,
        lease_in_seconds,
        mac: [0u8; 32],
    };

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts keys of any length");

    mac.update(&response.authentication_bytes());
    response.mac.copy_from_slice(&mac.finalize().into_bytes());

    response
}

#[derive(Debug)]
pub enum AuthError {
    UnknownDevice,
    InvalidSecret,
    InvalidRequest,
    InvalidMac,
    TimestampOutOfRange,
    ClockError,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnknownDevice => "unknown device",
            Self::InvalidSecret => "invalid device secret",
            Self::InvalidRequest => "invalid request",
            Self::InvalidMac => "invalid request authentication code",
            Self::TimestampOutOfRange => "request timestamp is outside the permitted window",
            Self::ClockError => "system clock error",
        };

        formatter.write_str(message)
    }
}

impl std::error::Error for AuthError {}
