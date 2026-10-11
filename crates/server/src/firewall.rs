use std::net::IpAddr;
use std::process::Command;

const TABLE: &str = "inet";
const TABLE_NAME: &str = "filter";
const IPV4_SET: &str = "vps_access_v4"; //FIXME

pub fn init() -> Result<(), Box<dyn std::error::Error>> {
    run_nft(["add", "table", "inet", "filter"])?;

    run_nft([
        "add",
        "set",
        "inet",
        "filter",
        "vps_access_v4",
        "{",
        "type",
        "ipv4_addr",
        ".",
        "inet_service",
        ";",
        "}",
    ])?;

    run_nft([
        "add",
        "rule",
        "inet",
        "filter",
        "input",
        "ip",
        "saddr",
        ".",
        "tcp",
        "dport",
        "@vps_access_v4", //TODO
        "accept",
    ])?;

    Ok(())
}

pub fn allow(ip: IpAddr, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let address_family = match ip {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    };

    let status = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "filter",
            "input",
            address_family,
            "saddr",
            &ip.to_string(),
            "tcp",
            "dport",
            &port.to_string(),
            "accept",
        ])
        .status()?;

    if !status.success() {
        return Err(format!("nft failed with status {status}").into());
    }

    Ok(())
}

pub fn remove(ip: IpAddr, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let address_family = match ip {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    };

    let output = Command::new("nft")
        .args(["-a", "list", "chain", "inet", "filter", "input"])
        .output()?;

    if !output.status.success() {
        return Err("failed to list nftables input chain".into());
    }

    let rules = String::from_utf8(output.stdout)?;

    let rule_prefix = format!("{} saddr {} tcp dport {} accept", address_family, ip, port);

    let handle = rules.lines().find_map(|line| {
        if !line.contains(&rule_prefix) {
            return None;
        }

        line.split_whitespace()
            .collect::<Vec<_>>()
            .windows(2)
            .find_map(|window| {
                if window[0] == "handle" {
                    Some(window[1])
                } else {
                    None
                }
            })
    });

    let handle = match handle {
        Some(handle) => handle,
        None => return Ok(()),
    };

    let status = Command::new("nft")
        .args([
            "delete", "rule", "inet", "filter", "input", "handle", handle,
        ])
        .status()?;

    if !status.success() {
        return Err(format!("nft failed with status {status}").into());
    }

    Ok(())
}

fn run_nft<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("nft").args(args).status()?;
    if !status.success() {
        return Err(format!("nft command failed with status {status}").into());
    }

    Ok(())
}

pub fn grant_access(ip: IpAddr, port: u16, duration: std::time::Duration) {
    if let Err(error) = allow2(ip, port) {
        eprintln!("failed to grant firewall access to {ip}:{port}: {error}");
        return;
    }

    tokio::spawn(async move {
        tokio::time::sleep(duration).await;

        if let Err(error) = remove2(ip, port) {
            eprintln!("failed to remove firewall access for {ip}:{port}: {error}");
        }
    });
}

// via "set"
pub fn allow2(ip: IpAddr, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let set = match ip {
        IpAddr::V4(_) => IPV4_SET,
        IpAddr::V6(_) => {
            return Err("IPv6 firewall access is not implemented yet".into());
        }
    };

    let status = Command::new("nft")
        .args([
            "add",
            "element",
            TABLE,
            TABLE_NAME,
            set,
            &format!("{{ {ip} }}"),
        ])
        .status()?;

    if !status.success() {
        return Err(format!("nft failed with status {status}").into());
    }

    Ok(())
}

//via "set"
pub fn remove2(ip: IpAddr, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let set = match ip {
        IpAddr::V4(_) => IPV4_SET,
        IpAddr::V6(_) => {
            return Err("IPv6 firewall access is not implemented yet".into());
        }
    };

    let status = Command::new("nft")
        .args([
            "delete",
            "element",
            TABLE,
            TABLE_NAME,
            set,
            &format!("{{ {ip} }}"),
        ])
        .status()?;

    if !status.success() {
        return Err(format!("nft failed with status {status}").into());
    }

    Ok(())
}


mod mock {
//     use std::net::IpAddr;
//     use crate::config::{PortRule, TransportProtocol};
//
//     pub fn open(source_ip: IpAddr, ports: &[PortRule], lease_in_seconds: u32) {
//         println!(
//             "MOCK FIREWALL: opening access for {source_ip} for {lease_in_seconds} seconds"
//         );
//
//         for rule in ports {
//             let protocol = match rule.protocol {
//                 TransportProtocol::Tcp => "TCP",
//                 TransportProtocol::Udp => "UDP",
//             };
//
//             println!("MOCK FIREWALL: allow {protocol} port {}", rule.port);
//         }
//     }
//
//     pub fn close(source_ip: IpAddr, ports: &[PortRule]) {
//         println!("MOCK FIREWALL: closing access for {source_ip}");
//
//         for rule in ports {
//             let protocol = match rule.protocol {
//                 TransportProtocol::Tcp => "TCP",
//                 TransportProtocol::Udp => "UDP",
//             };
//
//             println!("MOCK FIREWALL: revoke {protocol} port {}", rule.port);
//         }
//     }
//

    use std::{
        collections::HashMap,
        net::IpAddr,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex, OnceLock,
        },
    };

    use tokio::time::{sleep, Duration};
    use crate::config::{PortRule, TransportProtocol};

    static ACTIVE_LEASES: OnceLock<Mutex<HashMap<IpAddr, u64>>> = OnceLock::new();
    static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

    fn active_leases() -> &'static Mutex<HashMap<IpAddr, u64>> {
        ACTIVE_LEASES.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub fn open(source_ip: IpAddr, ports: &[PortRule], lease_in_seconds: u32) {
        let lease_id = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);

        active_leases()
            .lock()
            .expect("active lease mutex poisoned")
            .insert(source_ip, lease_id);

        let ports: Vec<(&'static str, u16)> = ports
            .iter()
            .map(|rule| {
                let protocol = match rule.protocol {
                    TransportProtocol::Tcp => "TCP",
                    TransportProtocol::Udp => "UDP",
                };

                (protocol, rule.port)
            })
            .collect();

        println!(
            "MOCK FIREWALL: opening access for {source_ip} for {lease_in_seconds} seconds"
        );

        for (protocol, port) in &ports {
            println!("MOCK FIREWALL: allow {protocol} port {port}");
        }

        tokio::spawn(async move {
            sleep(Duration::from_secs(u64::from(lease_in_seconds))).await;

            let expired = {
                let mut leases = active_leases()
                    .lock()
                    .expect("active lease mutex poisoned");

                if leases.get(&source_ip) == Some(&lease_id) {
                    leases.remove(&source_ip);
                    true
                } else {
                    false
                }
            };

            if expired {
                println!("MOCK FIREWALL: lease expired for {source_ip}");

                for (protocol, port) in ports {
                    println!(
                        "MOCK FIREWALL: revoke {protocol} port {port} for {source_ip}"
                    );
                }
            }
        });
    }

    pub fn close(source_ip: IpAddr, ports: &[PortRule]) {
        let had_lease = active_leases()
            .lock()
            .expect("active lease mutex poisoned")
            .remove(&source_ip)
            .is_some();

        if !had_lease {
            println!("MOCK FIREWALL: no active lease for {source_ip}");
            return;
        }

        println!("MOCK FIREWALL: closing access for {source_ip}");

        for rule in ports {
            let protocol = match rule.protocol {
                TransportProtocol::Tcp => "TCP",
                TransportProtocol::Udp => "UDP",
            };

            println!("MOCK FIREWALL: revoke {protocol} port {} for {source_ip}", rule.port);
        }
    }

}
