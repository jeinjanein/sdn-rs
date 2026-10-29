use netconf::framing::EndOfMessageDecoder;

use crate::server_side::subsystem::Subsystem;

pub const MAXIMUM_SESSION_CHANNELS_PER_CONNECTION: usize = 4;

#[derive(Debug)]
pub struct ChannelData {
    activated_subsystem: Option<Subsystem>,
    framing_decoder: EndOfMessageDecoder,
    client_has_sent_eof: bool,
    client_has_sent_close: bool,
    server_has_requested_close: bool,
}

impl ChannelData {
    pub fn new() -> Self {
        Self {
            activated_subsystem: None,
            framing_decoder: EndOfMessageDecoder::new(),
            client_has_sent_eof: false,
            client_has_sent_close: false,
            server_has_requested_close: false,
        }
    }

    pub fn framing_decoder_mut(&mut self) -> &mut EndOfMessageDecoder {
        &mut self.framing_decoder
    }

    pub fn activated_subsystem(&self) -> Option<Subsystem> {
        self.activated_subsystem
    }

    pub fn may_activate_subsystem(&self) -> bool {
        self.activated_subsystem.is_none()
    }

    pub fn record_activated_subsystem(&mut self, subsystem: Subsystem) {
        debug_assert!(
            self.may_activate_subsystem(),
            "channel already had active subsystem"
        );

        self.activated_subsystem = Some(subsystem)
    }

    pub fn netconf_subsystem_is_activated(&self) -> bool {
        self.activated_subsystem == Some(Subsystem::Netconf)
    }

    pub fn client_has_sent_eof(&self) -> bool {
        self.client_has_sent_eof
    }

    pub fn record_client_has_sent_eof(&mut self) {
        self.client_has_sent_eof = true
    }

    pub fn client_has_sent_close(&self) -> bool {
        self.client_has_sent_close
    }

    pub fn record_client_has_sent_close(&mut self) {
        self.client_has_sent_close = true
    }

    pub fn server_has_requested_close(&self) -> bool {
        self.server_has_requested_close
    }

    pub fn record_server_has_requested_close(&mut self) {
        self.server_has_requested_close = true
    }
}
