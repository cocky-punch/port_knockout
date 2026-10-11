use serde::Deserialize;
use std::{fs, net::SocketAddr};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub bind_address_ipv4: SocketAddr,
    pub bind_address_ipv6: SocketAddr,
    pub server_secret: String,
    pub lease_in_seconds: u32,
    pub devices: Vec<Device>,
    pub ports: Vec<PortRule>,
}

#[derive(Debug, Deserialize)]
pub struct Device {
    pub id: String,
    pub secret: String,
}

#[derive(Debug, Deserialize)]
pub struct PortRule {
    pub protocol: TransportProtocol,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

pub fn load() -> Result<Config, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string("./config.toml")?;
    let config: Config = toml::from_str(&contents)?;

    let server_secret = hex::decode(&config.server_secret)?;
    if server_secret.len() < 32 {
        return Err("server_secret must contain at least 32 random bytes".into());
    }

    if config.lease_in_seconds == 0 {
        return Err("lease_in_seconds must be greater than zero".into());
    }

    for device in &config.devices {
        if device.id.is_empty() || device.id.len() > 32 || device.id.as_bytes().contains(&0) {
            return Err(format!("invalid device ID: {:?}", device.id).into());
        }

        let secret = hex::decode(&device.secret)?;
        if secret.len() < 32 {
            return Err(format!(
                "secret for device {:?} must contain at least 32 random bytes",
                device.id
            )
            .into());
        }
    }

    validate_ports(&config.ports)?;
    Ok(config)
}

fn validate_ports(ports: &[PortRule]) -> Result<(), Box<dyn std::error::Error>> {
    if ports.is_empty() {
        return Err("at least one port must be configured".into());
    }

    for rule in ports {
        if rule.port == 0 {
            return Err("port 0 is not permitted".into());
        }
    }

    Ok(())
}
