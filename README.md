# Port knockout
A daemon that grants access to the certain list of ports for a client, IP, with a special knock.


## Vamos

### Server

Configure `config.toml` with the bind addresses, lease timeout, authorised devices and permitted ports.

The `ports` list defines which TCP and UDP ports the service is allowed to open. For example:

```toml
server_secret = "<generate yours>"
lease_in_seconds = 300

[[devices]]
id = "desktop-01"
secret = "<generate yours>"

[[ports]]
protocol = "udp"
port = 51820

[[ports]]
protocol = "tcp"
port = 22
```

Start the server with sufficient privileges to manage `nftables`.

### Client

Configure `crates/client/client.toml` with the server address, device ID, device secret and renewal interval.

Open access:

```bash
cargo run -p port_knockout_client -- open
```

Renewal requests are sent periodically while the client runs.

Revoke access early:

```bash
cargo run -p port_knockout_client -- end-session
```

### Selection of the ports

The list of `ports` of the server defines the permitted ports. In the current implementation, the client doesn't select the individual ports to open: an `open` request grants access to all configured ports.
