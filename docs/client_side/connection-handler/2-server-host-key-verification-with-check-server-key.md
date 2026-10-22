# Server Host-key verification
In the Secure Shell (SSH) architecture defined by [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html) and the Transport Layer Protocol defined by [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html), key exchange establishes a shared secret and symmetric encryption keys between two parties over an untrusted network. Diffie-Hellman key exchange by itself only guarantees that the two communicating endpoints share the same secret. It does not tell the client who the other endpoint is.

Without verifying the server's identity, an active attacker positioned between the client and the server can intercept the TCP connection and perform two separate SSH handshakes: one pretending to be the server toward the client, and another pretending to be the client toward the real server. If the client accepts the attacker's public host key, the client will encrypt and send its user authentication credentials (such as passwords or signatures) directly to the attacker.

To prevent this man-in-the-middle attack, [RFC 4251 Section 4.1](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.1) requires every SSH server to posses one or more asymmetric host keys and requires the client to verify that the presented public host key belongs to the intended host before trusting the session.

# How the SSH transport protocol splits verification into two checks
During the Diffie-Hellman key exchange specified in [RFC 4253 Section 8](https://www.rfc-editor.org/rfc/rfc4253.html#section-8), the client sends an ephemeral public value (`e`) and the server responds with a key-exchange reply message (`SSH_MSG_KEXDH_REPLY`) or (`SSH_MSG_KEX_ECDH_REPLY`) containing three values:
1. `K_S`: the server's public host key
2. `f`: the server's ephemeral key-exchange public value
3. `s`: a digital signature computed by the server over the exchange hash `H` using the private key corresponding to `K_S`

The exchange hash `H` binds together both parties's identification strings (`V_C` and `V_S`), both `SSH_MSG_KEXINIT` algorithm-negotation payloads (`I_C` and `I_S`), the server's public host key (`K_S`), the ephemeral values (`e` and `f`), and the derived shared secret (`K`).

RFC 4253 Section 8 requires the client to perform two separate verification steps upon receiving this reply:
1. Cryptographic signature verification: The client computes the exchange hash `H` and verifies that signature  `s` was produced over `H` by the private key corresponding to `K_S`. This proves that the remote peer currently terminating the key exchange possesses the private key for `K_S`
2. Host identity verification: The client verifies that the public key `K_S` actually belongs to the target host the client intended to reach. RFC 4251 Section 4.1 defines two standard ways to establish this trust: consulting a local database that associates host names or addresses with public key, or verifying a host certificate signed by a trusted certification authority (CA)

In `russh`, the library performs the first check automatically and delegates the second check to the application through `Handler::check_server_key`

# Where `check_server_key` runs in the `russh` handshake lifecycle
When a client starts an SSH session with `russh::client::connect` or `russh::client::connect_stream`, `russh` spawns a background session task and waits on an internal completion signal before returning a `russh::client::Handle` to the caller.

Inside that session task, `russh` executes the inital key exchange in the following order:
1. `russh` receives the server's key-exchange reply, parses `K_S` into an `ssh_key::Publickey`, computes the shared secret `K` and exchange hash `H`, and verifies the server's signature `s` against `H`. If the signature is invalid, `russh` immediately aborts the handshake with `russh::Error::WrongServerSig` and never calls `check_server_key`
2. `russh` sends `SSH_MSG_NEWKEYS` and waits to receive the server's `SSH_MSG_NEWKEYS` packet ([RFC 4253 Section 7.3](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.3))
3. Once both `SSH_MSG_NEWKEYS` messages have been exchanged for the initial handshake, `russh` calls `handler.kex_done(...)` and then awaits `handler.check_server_key(&server_host_key)`.
4. Only if `check_server_key` returns `Ok(true)` does `russh` transition the session into its encrypted state and send the internal completion signal that allows `connect` or `connect_stream` to return `Ok(Handle)`.

During subsequent key exchanges on the same connection (session rekeying, [RFC 4253 Section 9](https://www.rfc-editor.org/rfc/rfc4253.html#section-9)), `russh` recognizes that the session is already encrypted and does not call `check_server_key` a second time.

# The `check_server_key` trait method signature and outcomes
`russh::client::Handler` defines `check_server_key` with the following signature and default implementation:
```rust
pub trait Handler: Sized + Send {
    type Error: From<russh::Error> + Send + core::fmt::Debug;

    fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    // ...
}
```
## Parameters
- `&mut self`: Mutable access to the application's handler instance. `russh` does not pass a hostname, IP address, or a port to `check_server_key`. Because `russh::client::connect_stream` can run over any asynchronous byte stream, `russh` does not know the target host identity. Any handler that verifies keys by host and port must store that target identity as fields on `Self`
- `server_public_key: &ssh_key::Publickey`: The server's parsed public key (`K_S`) from the initial key exchange, after `russh` has already verified that the corresponding private key signed the exchange hash `H`.
## Return Outcomes
When `russh` awaits `handler.check_server_key(server_host_key)`, it evaluates the returned `Result<bool, Sekf::Error>`:
- `Ok(true)`: the handler accepts the server's public key. `russh` activates the negotiated encryption keys and returns the connected `Handle` from `connect` or `connect_stream`
- `Ok(false)`: The handler rejects the server's public key. `russh` converts `false` into `Self::Error::from(russh::Error::UnknownKey)`, shuts down the transport stream, and returns that error from `connect` or `connect_stream`.
- `Err(err)`: The handler aborts the check with a specific application or library error `err` or type `Self::Error`. `russh` propagates `err` directly out of `connect` or `connect_stream` and shuts down the transport stream.

