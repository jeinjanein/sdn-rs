use std::{borrow::Cow, time::Duration};

use russh::{
    Limits, Preferred, SshId, cipher,
    client::{Config, GexParams},
    compression, kex,
    keys::{Algorithm, EcdsaCurve, HashAlg},
    mac,
};

use crate::client_side::error::ClientError;

const CLIENT_ID: &str = "SSH-2.0-netconf-client_0.1.0";

const REKEY_WRITE_LIMIT: usize = 1 << 30; // 1 GiB

const REKEY_READ_LIMIT: usize = 1 << 30;

const REKEY_TIME_LIMIT: Duration = Duration::from_secs(60 * 60);

const INITIAL_WINDOW_SIZE: u32 = 2 * 1024 * 1024; // 2 MiB

const MAXIMUM_CHANNEL_PACKET_SIZE: u32 = 32 * 1024; // 32 KiB

const CHANNEL_MESSAGE_BUFFER_SIZE: usize = 100; // 100 unprocessed messages

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

const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10 * 60);

const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(60);

const KEEP_ALIVE_MAX: usize = 3;

const GEX_MIN_GROUP_SIZE: usize = 3072;

const GEX_PREFERRED_GROUP_SIZE: usize = 8192;

const GEX_MAX_GROUP_SIZE: usize = 8192;

fn allowed_ssh_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(ALLOWED_KEX_EXCHANGE_ALGORITHMS),
        key: Cow::Borrowed(ALLOWED_HOST_KEY_ALGORITHMS),
        cipher: Cow::Borrowed(ALLOWED_ENCRYPTION_ALGORITHMS),
        mac: Cow::Borrowed(ALLOWED_MESSAGE_AUTHENTICATION_ALGORITHMS),
        compression: Cow::Borrowed(ALLOWED_COMPRESSION_ALGORITHMS),
    }
}

fn gex_algorithms() -> Result<GexParams, ClientError> {
    let gex = GexParams::new(
        GEX_MIN_GROUP_SIZE,
        GEX_PREFERRED_GROUP_SIZE,
        GEX_MAX_GROUP_SIZE,
    )?;

    Ok(gex)
}

pub fn create_client_config() -> Result<Config, ClientError> {
    Ok(Config {
        client_id: SshId::Standard(Cow::Borrowed(CLIENT_ID)),

        limits: Limits {
            rekey_write_limit: REKEY_WRITE_LIMIT,
            rekey_read_limit: REKEY_READ_LIMIT,
            rekey_time_limit: REKEY_TIME_LIMIT,
        },

        window_size: INITIAL_WINDOW_SIZE,

        maximum_packet_size: MAXIMUM_CHANNEL_PACKET_SIZE,

        channel_buffer_size: CHANNEL_MESSAGE_BUFFER_SIZE,

        preferred: allowed_ssh_algorithms(),

        inactivity_timeout: Some(INACTIVITY_TIMEOUT),

        keepalive_interval: Some(KEEP_ALIVE_INTERVAL),

        keepalive_max: KEEP_ALIVE_MAX,

        anonymous: false,

        gex: gex_algorithms()?,

        nodelay: true,
    })
}