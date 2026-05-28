mod crypto;
mod routing;
mod transport;
mod tunnel;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rand::Rng;

#[derive(Parser)]
#[command(name = "dvion", about = "Quantum-secure VPN (ML-KEM-768 + X25519 + ChaCha20-Poly1305 over QUIC)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as VPN server
    Server {
        /// UDP address to listen on
        #[arg(long, default_value = "0.0.0.0:51820")]
        listen: String,

        /// TUN interface IP (server side)
        #[arg(long, default_value = "10.0.0.1")]
        tun_ip: String,

        /// Path to file containing valid auth keys (one per line)
        #[arg(long, default_value = "/etc/dvion/keys.txt")]
        keys_file: String,

        /// Enable NAT so clients can reach the internet through this server
        #[arg(long, default_value_t = false)]
        nat: bool,

        /// Directory to store the persistent TLS cert/key (server.crt + server.key)
        #[arg(long, default_value = "/etc/dvion")]
        cert_dir: String,
    },
    /// Run as VPN client
    Client {
        /// Server address (host:port)
        #[arg(long)]
        server: String,

        /// Auth key provided to you by dvion
        #[arg(long)]
        auth_key: String,

        /// Route ALL traffic through the VPN (browser, apps, everything)
        #[arg(long, default_value_t = false)]
        full_tunnel: bool,

        /// SHA-256 fingerprint of the server's TLS cert (colon-separated hex, e.g. AA:BB:CC:...)
        /// Run the server once to print its fingerprint, then pass it here.
        /// Omitting this flag skips cert verification — insecure, use only for testing.
        #[arg(long)]
        server_fingerprint: Option<String>,
    },
    /// Generate a new random auth key
    Keygen,
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "dvion_vpn=debug,info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Server { listen, tun_ip, keys_file, nat, cert_dir } => {
            transport::run_server(&listen, &tun_ip, &keys_file, nat, &cert_dir).await?;
        }
        Command::Client { server, auth_key, full_tunnel, server_fingerprint } => {
            let fp = server_fingerprint
                .as_deref()
                .map(transport::parse_fingerprint)
                .transpose()?;
            transport::run_client(&server, &auth_key, full_tunnel, fp).await?;
        }
        Command::Keygen => {
            let key = generate_key();
            println!("{key}");
        }
    }

    Ok(())
}

fn generate_key() -> String {
    let mut rng = rand::thread_rng();
    let key: String = (0..32)
        .map(|_| {
            let idx = rng.gen_range(0..36usize);
            if idx < 10 {
                (b'0' + idx as u8) as char
            } else {
                (b'a' + (idx - 10) as u8) as char
            }
        })
        .collect();
    format!("dvion-{key}")
}
