use std::{
    error::Error,
    net::IpAddr,
    process::Output,
};

use tokio::process::Command;
use crate::config::{PortRule, TransportProtocol};

const TABLE: &str = "filter";
const INPUT_CHAIN: &str = "input";
const ACCESS_CHAIN: &str = "vps_access";

type FirewallResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub async fn init(ports: &[PortRule]) -> FirewallResult<()> {
    nft(&["list", "table", "inet", TABLE]).await?;

    if nft(&["list", "chain", "inet", TABLE, INPUT_CHAIN])
        .await
        .is_err()
    {
        return Err(format!(
            "required nftables chain inet {TABLE} {INPUT_CHAIN} does not exist"
        )
        .into());
    }

    if nft(&["list", "chain", "inet", TABLE, ACCESS_CHAIN])
        .await
        .is_err()
    {
        nft(&["add", "chain", "inet", TABLE, ACCESS_CHAIN]).await?;
    }

    for rule in ports {
        for ipv6 in [false, true] {
            let set = set_name(rule, ipv6);
            let address_type = if ipv6 { "ipv6_addr" } else { "ipv4_addr" };

            if nft(&["list", "set", "inet", TABLE, &set])
                .await
                .is_err()
            {
                nft(&[
                    "add",
                    "set",
                    "inet",
                    TABLE,
                    &set,
                    &format!(
                        "{{ type {address_type}; flags timeout; timeout 5m; }}"
                    ),
                ])
                .await?;
            }

            let (family_match, protocol_match) = match (ipv6, &rule.protocol) {
                (false, TransportProtocol::Tcp) => ("ip saddr", "tcp"),
                (false, TransportProtocol::Udp) => ("ip saddr", "udp"),
                (true, TransportProtocol::Tcp) => ("ip6 saddr", "tcp"),
                (true, TransportProtocol::Udp) => ("ip6 saddr", "udp"),
            };

            let rule_text = format!(
                "{family_match} @{set} {protocol_match} dport {} accept",
                rule.port
            );

            let chain = nft(&["list", "chain", "inet", TABLE, ACCESS_CHAIN]).await?;

            if !String::from_utf8_lossy(&chain.stdout).contains(&rule_text) {
                nft(&[
                    "add",
                    "rule",
                    "inet",
                    TABLE,
                    ACCESS_CHAIN,
                    family_match,
                    &format!("@{set}"),
                    protocol_match,
                    "dport",
                    &rule.port.to_string(),
                    "accept",
                ])
                .await?;
            }
        }
    }

    let input = nft(&["list", "chain", "inet", TABLE, INPUT_CHAIN]).await?;

    if !String::from_utf8_lossy(&input.stdout).contains("jump vps_access") {
        nft(&[
            "insert",
            "rule",
            "inet",
            TABLE,
            INPUT_CHAIN,
            "jump",
            ACCESS_CHAIN,
        ])
        .await?;
    }

    Ok(())
}

pub async fn open(
    source_ip: IpAddr,
    ports: &[PortRule],
    lease_seconds: u32,
) -> FirewallResult<()> {
    if lease_seconds == 0 {
        return Err("lease duration must be greater than zero".into());
    }

    for rule in ports {
        let set = set_name(rule, source_ip.is_ipv6());
        let address = source_ip.to_string();
        let element = format!(
            "{{ {address} timeout {lease_seconds}s }}"
        );

        let replace = nft(&[
            "replace",
            "element",
            "inet",
            TABLE,
            &set,
            &element,
        ])
        .await;

        if replace.is_err() {
            nft(&[
                "add",
                "element",
                "inet",
                TABLE,
                &set,
                &element,
            ])
            .await?;
        }
    }

    Ok(())
}

pub async fn close(
    source_ip: IpAddr,
    ports: &[PortRule],
) -> FirewallResult<()> {
    let address = source_ip.to_string();

    for rule in ports {
        let set = set_name(rule, source_ip.is_ipv6());
        let element = format!("{{ {address} }}");

        let output = Command::new("nft")
            .args([
                "delete",
                "element",
                "inet",
                TABLE,
                &set,
                &element,
            ])
            .output()
            .await?;

        // Deleting a missing element is harmless.
        // Other failures should be reported.
        if !output.status.success()
            && !String::from_utf8_lossy(&output.stderr)
                .contains("No such file or directory")
            && !String::from_utf8_lossy(&output.stderr)
                .contains("No such element")
        {
            return Err(format!(
                "nft delete element failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
    }

    Ok(())
}

fn set_name(rule: &PortRule, ipv6: bool) -> String {
    let protocol = match rule.protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
    };

    format!(
        "vpa_{protocol}_{}{suffix}",
        rule.port,
        suffix = if ipv6 { "_v6" } else { "_v4" }
    )
}

async fn nft(args: &[&str]) -> FirewallResult<Output> {
    let output = Command::new("nft").args(args).output().await?;

    if !output.status.success() {
        return Err(format!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }

    Ok(output)
}
