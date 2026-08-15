use std::{borrow::Cow, path::Path, time::Duration};

use russh::{
    Limits, MethodKind, MethodSet, Preferred, SshId, cipher, compression, kex,
    keys::{Algorithm, EcdsaCurve, HashAlg, PrivateKey, load_secret_key},
    mac,
    server::Config,
};

use crate::server_side::error::ServerError;

const SEVER_ID: &str = "SSH-2.0-netconf_0.1.0";

const AUTHENTICATION_REJECTION_TIME: Duration = Duration::from_secs(1);

const AUTHENTICATION_REJECTION_TIME_INITIAL: Option<Duration> = None;

const REKEY_WRITE_LIMIT: usize = 1 << 30; // 1 GiB

const REKEY_READ_LIMIT: usize = 1 << 30;

const REKEY_TIME_LIMIT: Duration = Duration::from_secs(60 * 60);

const INITIAL_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MiB

const MAXIMUM_CHANNEL_PACKET_SIZE: u32 = 32 * 1024; // 32 KiB

const CHANNEL_MESSAGE_BUFFER_SIZE: usize = 100; // 100 unprocessed messages

const EVENT_BUFFER_SIZE: usize = 10;

// default KEX algorithms of russh
const ALLOWED_KEX_EXCHANGE_ALGORITHMS: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

// default key algorithms of russh
const ALLOWED_HOST_KEY_ALGORITHMS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    },
    Algorithm::Rsa {
        hash: Some(HashAlg::Sha256),
    },
    Algorithm::Rsa { hash: None },
];

// default encryption algorithms of russh
const ALLOWED_ENCRYPTION_ALGORITHMS: &[cipher::Name] = &[
    cipher::CHACHA20_POLY1305,
    cipher::AES_256_GCM,
    cipher::AES_256_CTR,
    cipher::AES_192_CTR,
    cipher::AES_128_CTR,
];

// default authentication algorithms of russh
const ALLOWED_MESSAGE_AUTHENTICATION_ALGORITHMS: &[mac::Name] = &[
    mac::HMAC_SHA512_ETM,
    mac::HMAC_SHA256_ETM,
    mac::HMAC_SHA512,
    mac::HMAC_SHA256,
];

// default compression algorithms of russh
const ALLOWED_COMPRESSION_ALGORITHMS: &[compression::Name] = &[compression::NONE];

const MAX_AUTHENTICATION_ATTEMPS: usize = 3;

const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10 * 60);

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(60);

const KEEP_ALIVE_MAX: usize = 3;

fn authentication_methods() -> MethodSet {
    MethodSet::from([MethodKind::PublicKey, MethodKind::Password].as_slice())
}

fn load_private_key(private_key_path: impl AsRef<Path>) -> Result<PrivateKey, ServerError> {
    load_secret_key(private_key_path.as_ref(), None)
        .map_err(|error| ServerError::Key { source: error })
}

fn allowed_ssh_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(ALLOWED_KEX_EXCHANGE_ALGORITHMS),
        key: Cow::Borrowed(ALLOWED_HOST_KEY_ALGORITHMS),
        cipher: Cow::Borrowed(ALLOWED_ENCRYPTION_ALGORITHMS),
        mac: Cow::Borrowed(ALLOWED_MESSAGE_AUTHENTICATION_ALGORITHMS),
        compression: Cow::Borrowed(ALLOWED_COMPRESSION_ALGORITHMS),
    }
}

pub fn create_server_config(
    private_key_path: impl AsRef<Path>,
) -> Result<Config, ServerError> {
    let private_key = load_private_key(private_key_path)?;

    Ok(Config {
        server_id: SshId::Standard(Cow::Borrowed(SEVER_ID)),

        methods: authentication_methods(),

        auth_rejection_time: AUTHENTICATION_REJECTION_TIME,

        auth_rejection_time_initial: AUTHENTICATION_REJECTION_TIME_INITIAL,

        keys: vec![private_key],

        limits: Limits {
            rekey_write_limit: REKEY_WRITE_LIMIT,
            rekey_read_limit: REKEY_READ_LIMIT,
            rekey_time_limit: REKEY_TIME_LIMIT,
        },

        window_size: INITIAL_WINDOW_SIZE,

        maximum_packet_size: MAXIMUM_CHANNEL_PACKET_SIZE,

        channel_buffer_size: CHANNEL_MESSAGE_BUFFER_SIZE,

        event_buffer_size: EVENT_BUFFER_SIZE,

        preferred: allowed_ssh_algorithms(),

        max_auth_attempts: MAX_AUTHENTICATION_ATTEMPS,

        inactivity_timeout: Some(INACTIVITY_TIMEOUT),

        keepalive_interval: Some(KEEP_ALIVE_INTERVAL),

        keepalive_max: KEEP_ALIVE_MAX,

        nodelay: true,
    })
}
