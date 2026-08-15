use std::sync::Arc;

use russh::{keys::load_public_key, server::Server};
use ssh::server_side::{config::create_server_config, server::SshServer};
use tokio::net::TcpListener;
use tracing::info;

mod logging;

const HOST_PRIVATE_KEY_PATH: &str = "./keys/host_ed25519_key";

const HOST_ADDRESS: &str = "127.0.0.1:2222";

const ADMIN_PUBLIC_KEY_PATH: &str = "./keys/admin_ed25519_key.pub";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::initialize();
    let config = Arc::new(create_server_config(HOST_PRIVATE_KEY_PATH)?);
    info!("Create server configuration");

    let bind_address = TcpListener::bind(HOST_ADDRESS).await?;
    info!("SSH server is listening");

    let admin_public_key = load_public_key(ADMIN_PUBLIC_KEY_PATH)?;

    let mut ssh_server = SshServer::new(vec![admin_public_key]);

    let mut running_server = ssh_server.run_on_socket(config, &bind_address);

    let shutdown_handle = running_server.handle();

    let shutdown_requested = tokio::select! {
        server_result = & mut running_server => {
            server_result?;

            false
        }

        signal_result = ssh::server_side::shutdown::wait_for_shutdown_signal() => {
            signal_result?;

            true
        }
    };

    if shutdown_requested {
        info!("shutdown signal received");

        shutdown_handle.shutdown("server shutdown requested".into());

        running_server.await?;
    }

    info!("SSH server stopped");

    Ok(())
}
