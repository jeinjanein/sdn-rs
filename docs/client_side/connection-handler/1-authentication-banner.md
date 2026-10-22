# What is Authentication Banner?
An SSH authentication banner (`SSH_MSG_USERAUTH_BANNER` in RFC 4252, Section 5.4) is an optional informational text message that an SSH server sends to the client during the user-authentication phase, after the encrypted transport and server host-key check have completed and before authentication finishes.

Network routers and switches commonly use this message to send a legal warning, security policy notice, or device identifiert (for example, `"Authorized access only"`).

# Key characteristics
- A banner does not grant or deny authentication, does not prompt for user input and requires no reply packet from the client
- The banner travels inside the SSh authentication protocol before any session channel or `netconf` subsystem is opened, so it never mixes with the NETCONF XML stream

# How `russh` and this project handle it
When `russh` receives `SSH_MSG_USERAUTH_BANNER` from the server, it calls `russh::client::Handler::auth_banner`:
```rust
async fn auth_banner(
    &mut self,
    banner: &str,
    session: &mut russh::client::Session,
) -> Result<(), Self::Error>
```
An interactive SSH client displays `banner` on the user's terminal. `ConnectionHandler::auth_banner` in `client_side/handler.rs` records the message in structured logs and returns `Ok(())` so authentication continues:

```rust
 async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            connection_id = self.connection_id(),
            peer_addr = ?self.peer_addr(),
            banner = ?banner,
            "SSH authentication banner received"
        );

        Ok(())
    }   
```