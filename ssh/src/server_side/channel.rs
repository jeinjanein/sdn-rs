use bytes::{Bytes, BytesMut};

use crate::server_side::error::ServerError;

pub const MAXIMUM_SESSION_CHANNELS_PER_CONNECTION: usize = 4;

pub const NETCONF_EOM_MARKER: &[u8] = b"]]>]]>";

pub const NETCONF_MAXIMUM_MESSAGE_LENGTH: usize = 1024 * 1024;

pub const NETCONF_MAXIMUM_INCOMPLETE_MESSAGE_LENGTH: usize =
    NETCONF_MAXIMUM_MESSAGE_LENGTH + NETCONF_EOM_MARKER.len() - 1;

#[derive(Debug)]
pub struct ChannelData {
    received_buffer: BytesMut,
}

impl ChannelData {
    pub fn new() -> Self {
        Self {
            received_buffer: BytesMut::new(),
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
}
