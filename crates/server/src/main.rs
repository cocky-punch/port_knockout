use tokio::net::UdpSocket;

mod auth;
mod config;
// mod protocol;
mod firewall2;

// use crate::protocol;
use port_knockout_protocol::{Request, RequestKind, Response, ResponseStatus};

const APP_NAME: &str = "port_knockout";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = config::load()?;
    firewall2::init(&config.ports);

    let ipv4_socket = UdpSocket::bind(config.bind_address_ipv4).await?;
    let ipv6_socket = UdpSocket::bind(config.bind_address_ipv6).await?;

    println!("{} listening on {}", APP_NAME, config.bind_address_ipv4);
    println!("{} listening on {}", APP_NAME, config.bind_address_ipv6);

    let ipv4_task = receive_loop(&ipv4_socket, &config);
    let ipv6_task = receive_loop(&ipv6_socket, &config);

    tokio::try_join!(ipv4_task, ipv6_task)?;

    Ok(())
}

async fn receive_loop(
    socket: &UdpSocket,
    config: &config::Config,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = [0u8; 2048];

    loop {
        let (length, source_addr) = socket.recv_from(&mut buffer).await?;
        let packet = &buffer[..length];

        let request = match port_knockout_protocol::Request::from_bytes(packet) {
            Ok(request) => request,
            Err(error) => {
                eprintln!("invalid packet from {source_addr}: {error}");
                continue;
            }
        };

        let response = match auth::handle_request(&request, config, source_addr.ip()) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("request from {source_addr} rejected: {error}");
                continue;
            }
        };

        let response_bytes = response.to_bytes();
        socket.send_to(&response_bytes, source_addr).await?;
    }
}
