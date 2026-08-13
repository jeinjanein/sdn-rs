use bytes::{Bytes, BytesMut};

use crate::server_side::{error::ServerError, subsystem::Subsystem};

pub const MAXIMUM_SESSION_CHANNELS_PER_CONNECTION: usize = 4;

pub const NETCONF_EOM_MARKER: &[u8] = b"]]>]]>";

pub const NETCONF_MAXIMUM_MESSAGE_LENGTH: usize = 1024 * 1024;

pub const NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH: usize =
    NETCONF_MAXIMUM_MESSAGE_LENGTH + NETCONF_EOM_MARKER.len() - 1;

#[derive(Debug)]
pub struct ChannelData {
    activated_subsystem: Option<Subsystem>,
    received_buffer: BytesMut,
    client_has_sent_eof: bool,
    client_has_sent_close: bool,
    server_has_requested_close: bool,
}

impl ChannelData {
    pub fn new() -> Self {
        Self {
            activated_subsystem: None,
            received_buffer: BytesMut::new(),
            client_has_sent_eof: false,
            client_has_sent_close: false,
            server_has_requested_close: false,
        }
    }

    pub fn received_buffer_bytes_count(&self) -> usize {
        self.received_buffer.len()
    }

    pub fn append_message_to_buffer(&mut self, data: &[u8]) {
        self.received_buffer.extend_from_slice(data);
    }

    fn extract_message_from_buffer(&mut self) -> Option<Bytes> {
        let Some(start_eom) = self
            .received_buffer
            .windows(NETCONF_EOM_MARKER.len())
            .position(|window| window == NETCONF_EOM_MARKER)
        else {
            return None;
        };

        let mut message = self
            .received_buffer
            .split_to(start_eom + NETCONF_EOM_MARKER.len());

        message.truncate(start_eom);

        Some(message.freeze())
    }

    fn verify_messages_size_limit(&self) -> Result<(), ServerError> {
        let mut remaining_bytes = self.received_buffer.as_ref();

        loop {
            let Some(start_eom) = remaining_bytes
                .windows(NETCONF_EOM_MARKER.len())
                .position(|window| window == NETCONF_EOM_MARKER)
            else {
                if remaining_bytes.len() > NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH {
                    return Err(ServerError::IncompleteMessageTooLarge {
                        message_size: remaining_bytes.len(),
                        maximum_size: NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH,
                    });
                }

                return Ok(());
            };

            if start_eom > NETCONF_MAXIMUM_MESSAGE_LENGTH {
                return Err(ServerError::MessageTooLarge {
                    message_size: start_eom,
                    maximum_size: NETCONF_MAXIMUM_MESSAGE_LENGTH,
                });
            }

            let message_length = start_eom + NETCONF_EOM_MARKER.len();

            remaining_bytes = &remaining_bytes[message_length..];
        }
    }

    pub fn extract_messages_from_buffer(&mut self) -> Result<Vec<Bytes>, ServerError> {
        self.verify_messages_size_limit()?;

        let mut messages = Vec::new();
        while let Some(message) = self.extract_message_from_buffer() {
            messages.push(message);
        }

        Ok(messages)
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

#[cfg(test)]
mod tests {
    use crate::server_side::{
        channel::{
            ChannelData, NETCONF_EOM_MARKER, NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH,
            NETCONF_MAXIMUM_MESSAGE_LENGTH,
        },
        error::ServerError,
    };

    #[test]
    fn complete_message_within_size_limit_is_accepted() {
        let mut channel_data = ChannelData::new();

        let mut valid_message = vec![b'x'; NETCONF_MAXIMUM_MESSAGE_LENGTH];

        valid_message.extend_from_slice(NETCONF_EOM_MARKER);

        channel_data.append_message_to_buffer(&valid_message);

        let extracted_messages = channel_data
            .extract_messages_from_buffer()
            .expect("a message within length limit is accepted");

        assert_eq!(extracted_messages.len(), 1);

        assert_eq!(extracted_messages[0].len(), NETCONF_MAXIMUM_MESSAGE_LENGTH);
    }

    #[test]
    fn complete_message_larger_than_size_limit_is_rejected() {
        let mut channel_data = ChannelData::new();

        let invalid_size = NETCONF_MAXIMUM_MESSAGE_LENGTH + 1;

        let mut invalid_message = vec![b'x'; invalid_size];

        invalid_message.extend_from_slice(NETCONF_EOM_MARKER);

        channel_data.append_message_to_buffer(&invalid_message);

        let extracted_messages_error = channel_data
            .extract_messages_from_buffer()
            .expect_err("oversized complete message should be rejected");

        assert!(matches!(
            extracted_messages_error,
            ServerError::MessageTooLarge { message_size, maximum_size }
            if message_size == invalid_size
            && maximum_size == NETCONF_MAXIMUM_MESSAGE_LENGTH
        ));
    }

    #[test]
    fn incomplete_message_larger_than_size_limit_is_rejected() {
        let mut channel_data = ChannelData::new();

        let invalid_size = NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH + 1;

        let invalid_message = vec![b'x'; invalid_size];

        channel_data.append_message_to_buffer(&invalid_message);

        let extracted_messages_error = channel_data
            .extract_messages_from_buffer()
            .expect_err("an incomplete message larger than length limit is rejected");

        assert!(matches!(
            extracted_messages_error,
            ServerError::IncompleteMessageTooLarge { message_size, maximum_size }
            if message_size == invalid_size && maximum_size == NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH
        ));
    }

    #[test]
    fn netconf_framing_marker_may_be_split_across_receive_calls() {
        let mut channel_data = ChannelData::new();

        let first_message_raw = channel_data.append_message_to_buffer(b"<rpc></rpc>]]>");

        let first_message_decoded = channel_data
            .extract_messages_from_buffer()
            .expect("should be empty");

        assert!(first_message_decoded.is_empty());

        let second_message_raw = channel_data.append_message_to_buffer(b"]]>");
        let second_message_decoded = channel_data
            .extract_messages_from_buffer()
            .expect("should contain one messsage");

        assert_eq!(second_message_decoded.len(), 1);

        assert_eq!(second_message_decoded[0].as_ref(), b"<rpc></rpc>");

        assert_eq!(channel_data.received_buffer_bytes_count(), 0);
    }
}
