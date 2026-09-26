# 1. Why SSH server host-key verification is mandatory
## 1.1 Encryption does not identify the server by itself
SSH key exchange creates encryption and integrity protection for the connection. During that exchange, the server proves that it holds the private key corresponding to the public host key it sent

That proof answers only one question: does this server hold this private key? It does not answer the question the controller (client) needs: does this key belong to the intended network device?

If the controller accepts any valid public key, an attacker who can intercept the connection can present the attackers's key and establish an encrypted SSH session with the client. The attacker can establish a separate session with the real device (server) and relay or alter traffic. Both connection can be encrypted while the client is still talking to the wrong peer.

Server host-key verification prevents this attack by binding the target identity to trusted key material. The client continues only when the received key is allowed for the device it intended to reach.

## 1.2 The trust decision must happen before authentication
The client must verify the server before it sends a password, attempts another user-authentication method, or opens a NETCONF channel. Rejecting the server later would expose credentials or application data before identity had been established

## 1.3 The callback
The SSH library can verify the signature made by the received host key, but it cannot know which keys this controller trusts for a particular device. `russh` therefore asks the application to make that policy decision through `russh::client::Handler::check_server_key`:
```rust
fn check_server_key(
    &mut self,
    server_public_key: &ssh_key::PublicKey,
) -> impl Future<Output = Result<bool, Self::Error>> + Send;
```
- `Ok(true)` means the application recognizes the key and permits the SSH handshake to continue
- `Ok(false)` means the application does not trust the key. `russh` stops the handshake with `russh::Error::UnknownKey`
- `Err(error)` means the application could not make the decision. The error also stops the handshake

## 1.4 Current behavior
```rust
async fn check_server_key(
    &mut self,
    _server_public_key: &russh::keys::PublicKey,
) -> Result<bool, Self::Error> {
    Ok(false)
}
```
The method rejects every key, so it is not yet useful for a production connection, but it does not create an unauthenticated path. 