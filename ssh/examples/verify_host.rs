use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Context;
use russh::keys::load_public_key;
use ssh::client_side::{
    config::create_client_config,
    connection::{create_ssh_connection, create_tcp_connection},
    error::ClientError,
    known_hosts::HostKeyPolicy,
    target::TargetIdentity,
};
use tokio::time::timeout;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let path = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .context("cargo run -p ssh --example verify_host -- <path>")?,
    );
    println!("{}", path.display());

    let key = load_public_key(&path)?;

    let host_key_policy = HostKeyPolicy::PinnedKey { key };

    let address: SocketAddr = "127.0.0.1:2222".parse()?;
    let config = Arc::new(create_client_config()?);
    let stream = create_tcp_connection(&[address]).await?;
    let target_identity = TargetIdentity::new("127.0.0.1".to_string(), 2222, Some(address));
    let mut client =
        create_ssh_connection(config, stream, target_identity, host_key_policy).await?;

    println!("Verified SSH host key for 127.0.0.1:2222; no user credentials sent.");
    let _ = timeout(Duration::from_secs(5), async {
        client
            .handle_mut()
            .disconnect(
                russh::Disconnect::ByApplication,
                "host verification completed",
                "en",
            )
            .await?;

        match client.handle_mut().await {
            Ok(())
            | Err(ClientError::Ssh {
                source: russh::Error::Disconnect,
            }) => Ok(()),
            Err(error) => Err(error),
        }
    })
    .await?;

    Ok(())
}
