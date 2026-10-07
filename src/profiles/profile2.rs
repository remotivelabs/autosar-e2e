//! # E2E Profile 2 Implementation
//!
//! Profile 2 puts the same bytes on the wire as profile 22 at offset 0: an 8-bit CRC in the first
//! byte, a 4-bit counter in the low nibble of the second, and a Data ID picked from a list of 16
//! by the counter. It differs in how a stream starts:
//! - the sender increments before it writes, so the first frame carries counter 1
//!   (E2E_P02ProtectStateType);
//! - the receiver waits for its first frame and takes that frame's counter as it is
//!   (WaitForFirstData in E2E_P02CheckStateType).
//!
//! # Data layout
//! [CRC(1B) | HDR(1B) | DATA ...]
//! - HDR (bits 3..0) : counter

use crate::profile22::{Profile22, Profile22Config};
use crate::{E2EProfile, E2EResult, E2EStatus};

const DATA_ID_NUMBER: usize = 16;

/// Configuration for E2E Profile 2
#[derive(Debug, Clone)]
pub struct Profile2Config {
    /// Length of Data, in bits. The value shall be a multiple of 8.
    pub data_length: usize,
    /// The Data IDs, one per counter value, for protection against masquerading.
    pub data_id_list: [u8; DATA_ID_NUMBER],
    /// Maximum allowed delta between consecutive counters
    pub max_delta_counter: u8,
}

impl Default for Profile2Config {
    fn default() -> Self {
        let Profile22Config {
            data_length,
            data_id_list,
            max_delta_counter,
            ..
        } = Profile22Config::default();
        Self {
            data_length,
            data_id_list,
            max_delta_counter,
        }
    }
}

impl From<Profile2Config> for Profile22Config {
    fn from(config: Profile2Config) -> Self {
        Self {
            data_length: config.data_length,
            data_id_list: config.data_id_list,
            max_delta_counter: config.max_delta_counter,
            offset: 0,
        }
    }
}

/// E2E Profile 2 Implementation
///
/// Implements AUTOSAR E2E Profile 2 protection mechanism
#[derive(Clone)]
pub struct Profile2 {
    wire: Profile22,
    waiting_for_first_data: bool,
}

impl E2EProfile for Profile2 {
    type Config = Profile2Config;

    fn new(config: Self::Config) -> E2EResult<Self> {
        let mut wire = Profile22::new(config.into())?;
        wire.set_counter(1)?;
        Ok(Self {
            wire,
            waiting_for_first_data: true,
        })
    }

    fn protect(&mut self, data: &mut [u8]) -> E2EResult<()> {
        self.wire.protect(data)
    }

    fn set_counter(&mut self, counter: u32) -> E2EResult<()> {
        self.wire.set_counter(counter)
    }

    fn check(&mut self, data: &[u8]) -> E2EResult<E2EStatus> {
        let status = self.wire.check(data)?;
        if self.waiting_for_first_data && status != E2EStatus::CrcError {
            self.waiting_for_first_data = false;
            return Ok(E2EStatus::Ok);
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile 2 CRC: over the data after the CRC byte, then the counter's Data ID.
    #[test]
    fn test_profile2_first_frame_carries_counter_one() {
        let vectors: &[(u8, &[u8], u8)] = &[
            (0x12, &[0x01, 0x02, 0x03], 0x5f),
            (0xff, &[0x01, 0x02, 0x03], 0xed),
            (0xa5, &[0x01, 0x23, 0x45, 0x67, 0x89], 0x1a),
        ];
        for (data_id, data, expected) in vectors {
            let mut data_id_list = [0u8; DATA_ID_NUMBER];
            data_id_list[1] = *data_id;
            let config = Profile2Config {
                data_length: (data.len() + 1) * 8,
                data_id_list,
                ..Default::default()
            };
            let mut profile_tx = Profile2::new(config.clone()).unwrap();
            let mut profile_rx = Profile2::new(config).unwrap();
            let mut frame = [&[0x00], *data].concat();

            profile_tx.protect(&mut frame).unwrap();

            assert_eq!(&frame[1..], *data, "data_id {data_id:#04x}");
            assert_eq!(frame[0], *expected, "data_id {data_id:#04x}");
            assert_eq!(profile_rx.check(&frame).unwrap(), E2EStatus::Ok);
        }
    }

    #[test]
    fn test_profile2_counts_one_to_fifteen_then_zero() {
        let mut profile = Profile2::new(Profile2Config::default()).unwrap();
        let mut data = vec![0x00; 8];
        let counters: Vec<u8> = (0..17)
            .map(|_| {
                profile.protect(&mut data).unwrap();
                data[1] & 0x0F
            })
            .collect();
        assert_eq!(
            counters,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1]
        );
    }

    /// A receiver takes its first frame's counter as it is, wherever the stream is.
    #[test]
    fn test_profile2_receiver_takes_any_first_counter() {
        let mut profile_tx = Profile2::new(Profile2Config::default()).unwrap();
        let mut profile_rx = Profile2::new(Profile2Config::default()).unwrap();
        let mut data = vec![0x00; 8];
        profile_tx.set_counter(9).unwrap();

        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Repeated);
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
    }

    #[test]
    fn test_profile2_first_frame_with_a_bad_crc_is_a_crc_error_and_it_still_waits() {
        let mut profile_tx = Profile2::new(Profile2Config::default()).unwrap();
        let mut profile_rx = Profile2::new(Profile2Config::default()).unwrap();
        let mut data = vec![0x00; 8];
        profile_tx.set_counter(9).unwrap();
        profile_tx.protect(&mut data).unwrap();
        let mut corrupted = data.clone();
        corrupted[0] ^= 0xFF;

        assert_eq!(profile_rx.check(&corrupted).unwrap(), E2EStatus::CrcError);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
    }
}
