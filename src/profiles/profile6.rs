//! # E2E Profile 6 Implementation
//!
//! Profile 6 is designed for protecting large data packets
//! with low overhead. It uses:
//! - 16-bit CRC for data integrity
//! - 8-bit counter for sequence checking
//! - 16-bit Data ID for masquerade prevention
//! - 16-bit Data Length to support dynamic size data
//!
//! # Data layout
//! [DATA ... | CRC(2B) | LENGTH(2B) | COUNTER(1B) | DATA ...]
use crate::{E2EError, E2EProfile, E2EResult, E2EStatus};
use crc::{Crc, CRC_16_IBM_3740};

// Constants
const BITS_PER_BYTE: u16 = 8;
const COUNTER_MAX: u8 = 0xFF;
const COUNTER_MODULO: u16 = 0x100;

/// Configuration for E2E Profile 6
#[derive(Debug, Clone)]
pub struct Profile6Config {
    /// data id
    pub data_id: u16,
    /// Bit offset of the first bit of the E2E header from the beginning of the Data
    pub offset: u16,
    /// Minimal length of Data, in bits
    pub min_data_length: u16,
    /// Maximal length of Data, in bits
    pub max_data_length: u16,
    /// Maximum allowed delta between consecutive counters
    pub max_delta_counter: u8,
}

/// Check Item for E2E Profile 6
#[derive(Debug, Clone)]
pub struct Profile6Check {
    rx_data_length: u16,
    rx_counter: u8,
    rx_crc: u16,
    calculated_crc: u16,
    data_len: u16,
}

impl Default for Profile6Config {
    fn default() -> Self {
        Self {
            data_id: 0x1234,
            offset: 0x0000,
            min_data_length: 40,    // 5bytes
            max_data_length: 32768, // 4096bytes
            max_delta_counter: 1,
        }
    }
}

/// E2E Profile 6 Implementation
///
/// Implements AUTOSAR E2E Profile 6 protection mechanism
#[derive(Clone)]
pub struct Profile6 {
    config: Profile6Config,
    counter: u8,
    received_counter: u8,
}

impl Profile6 {
    /// Validate configuration parameters
    fn validate_config(config: &Profile6Config) -> E2EResult<()> {
        if config.min_data_length < 5 * BITS_PER_BYTE
            || 4096 * BITS_PER_BYTE < config.min_data_length
        {
            return Err(E2EError::InvalidConfiguration(
                "Minimum Data length shall be between 5B and 4096B".into(),
            ));
        }
        if config.max_data_length < config.min_data_length || 4096 * 8 < config.max_data_length {
            return Err(E2EError::InvalidConfiguration(
                "Maximum Data length shall be between MinDataLength and 4096B".into(),
            ));
        }
        if !config.offset.is_multiple_of(BITS_PER_BYTE)
            || config.max_data_length - 5 * BITS_PER_BYTE < config.offset
        {
            return Err(E2EError::InvalidConfiguration(
                "Offset shall be a multiple of 8 between 0 and MaxDataLength - 5B".into(),
            ));
        }
        if config.max_delta_counter == 0 || config.max_delta_counter == COUNTER_MAX {
            return Err(E2EError::InvalidConfiguration(format!(
                "Max delta counter must be between 1 and {}",
                COUNTER_MAX
            )));
        }
        Ok(())
    }
    /// Validate data length against min/max constraints
    fn validate_length(&self, len: u16) -> E2EResult<()> {
        let header_end = self.config.offset / BITS_PER_BYTE + 5;
        if len < header_end {
            return Err(E2EError::InvalidDataFormat(format!(
                "Expected at least {} bytes to hold the header, got {} bytes",
                header_end, len
            )));
        }
        let min_bytes = self.config.min_data_length / BITS_PER_BYTE;
        let max_bytes = self.config.max_data_length / BITS_PER_BYTE;
        if len < min_bytes || max_bytes < len {
            return Err(E2EError::InvalidDataFormat(format!(
                "Expected {} - {} bytes, got {} bytes",
                min_bytes, max_bytes, len
            )));
        }
        Ok(())
    }
    fn write_data_length(&self, data: &mut [u8]) {
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        let len16 = data.len() as u16;
        data[offset + 2..=offset + 3].copy_from_slice(&len16.to_be_bytes());
    }
    fn write_counter(&self, data: &mut [u8]) {
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        data[offset + 4] = self.counter;
    }
    fn compute_crc(&self, data: &[u8]) -> u16 {
        let crc: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);
        let mut digest = crc.digest();
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        digest.update(&data[0..offset]); // crc calculation data before offset
        digest.update(&data[(offset + 2)..]); // crc calculation data after offset
        digest.update(&self.config.data_id.to_be_bytes());
        digest.finalize()
    }
    fn write_crc(&self, calculated_crc: u16, data: &mut [u8]) {
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        data[offset..=offset + 1].copy_from_slice(&calculated_crc.to_be_bytes());
    }
    fn increment_counter(&mut self) {
        self.counter = (self.counter as u16 + 1) as u8 & COUNTER_MAX;
    }

    fn read_data_length(&self, data: &[u8]) -> u16 {
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        u16::from_be_bytes([data[offset + 2], data[offset + 3]])
    }
    fn read_counter(&self, data: &[u8]) -> u8 {
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        data[offset + 4]
    }
    fn read_crc(&self, data: &[u8]) -> u16 {
        let offset = (self.config.offset / BITS_PER_BYTE) as usize;
        u16::from_be_bytes([data[offset], data[offset + 1]])
    }

    fn do_checks(&mut self, check_items: Profile6Check) -> E2EStatus {
        if check_items.calculated_crc != check_items.rx_crc {
            return E2EStatus::CrcError;
        }
        if check_items.rx_data_length != check_items.data_len {
            return E2EStatus::DataLengthError;
        }
        let status = self.validate_counter(check_items.rx_counter);
        self.received_counter = check_items.rx_counter;
        status
    }
    /// Check if counter delta is within acceptable range
    fn check_counter_delta(&self, rx_counter: u8) -> u8 {
        if rx_counter >= self.received_counter {
            rx_counter - self.received_counter
        } else {
            // Handle wrap-around
            ((COUNTER_MODULO + rx_counter as u16 - self.received_counter as u16) % COUNTER_MODULO)
                as u8
        }
    }
    fn validate_counter(&self, rx_counter: u8) -> E2EStatus {
        match self.check_counter_delta(rx_counter) {
            0 => E2EStatus::Repeated,
            1 => E2EStatus::Ok,
            delta if delta <= self.config.max_delta_counter => E2EStatus::OkSomeLost,
            _ => E2EStatus::WrongSequence,
        }
    }
}

impl E2EProfile for Profile6 {
    type Config = Profile6Config;

    fn new(config: Self::Config) -> E2EResult<Self> {
        // Validate config
        Self::validate_config(&config)?;
        Ok(Self {
            config,
            counter: 0,
            // Starts at the maximum, as E2E_P06CheckInit does: one step before a stream's first 0.
            received_counter: COUNTER_MAX,
        })
    }

    fn protect(&mut self, data: &mut [u8]) -> E2EResult<()> {
        self.validate_length(data.len() as u16)?;
        self.write_data_length(data);
        self.write_counter(data);
        let calculated_crc = self.compute_crc(data);
        self.write_crc(calculated_crc, data);
        self.increment_counter();
        Ok(())
    }

    fn set_counter(&mut self, counter: u32) -> E2EResult<()> {
        if counter > u32::from(COUNTER_MAX) {
            return Err(E2EError::InvalidCounter {
                counter,
                max: u32::from(COUNTER_MAX),
            });
        }
        self.counter = counter as u8;
        Ok(())
    }

    fn check(&mut self, data: &[u8]) -> E2EResult<E2EStatus> {
        // Check data length
        self.validate_length(data.len() as u16)?;
        let check_items = Profile6Check {
            rx_data_length: self.read_data_length(data),
            rx_counter: self.read_counter(data),
            rx_crc: self.read_crc(data),
            calculated_crc: self.compute_crc(data),
            data_len: data.len() as u16,
        };
        Ok(self.do_checks(check_items))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_profile6_basic_example() {
        let mut profile_tx = Profile6::new(Profile6Config::default()).unwrap();
        let mut profile_rx = Profile6::new(Profile6Config::default()).unwrap();

        let mut data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        profile_tx.protect(&mut data).unwrap();
        // CRC check
        assert_eq!(data[0], 0xb1);
        assert_eq!(data[1], 0x55);
        // length check
        assert_eq!(data[2], 0x00);
        assert_eq!(data[3], 0x08);
        // counter check
        assert_eq!(data[4], 0x00);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
    }

    #[test]
    fn test_profile6_offset_example() {
        let config = Profile6Config {
            offset: 64,
            ..Default::default()
        };

        let mut profile_tx = Profile6::new(config.clone()).unwrap();
        let mut profile_rx = Profile6::new(config).unwrap();

        let mut data = vec![
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        profile_tx.protect(&mut data).unwrap();
        // crc check
        assert_eq!(data[8], 0x4e);
        assert_eq!(data[9], 0xb7);
        // length check
        assert_eq!(data[10], 0x00);
        assert_eq!(data[11], 0x10);
        // counter check
        assert_eq!(data[12], 0x00);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
    }
    #[test]
    fn test_profile6_counter_wraparound() {
        let mut profile_tx = Profile6::new(Profile6Config::default()).unwrap();
        let mut profile_rx = Profile6::new(Profile6Config::default()).unwrap();

        let mut data = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        profile_tx.protect(&mut data).unwrap();
        // counter check
        assert_eq!(data[4], 0x00);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        profile_tx.protect(&mut data).unwrap();
        // counter check
        assert_eq!(data[4], 0x01);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        profile_rx.received_counter = 0xFE;
        profile_tx.counter = 0xFF;
        profile_tx.protect(&mut data).unwrap();
        // counter check
        assert_eq!(data[4], 0xFF);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        profile_tx.protect(&mut data).unwrap();
        // counter check
        assert_eq!(data[4], 0x00);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        profile_tx.protect(&mut data).unwrap();
    }

    #[test]
    fn test_profile6_fresh_receiver_follows_a_fresh_sender_from_counter_zero() {
        let mut profile_tx = Profile6::new(Profile6Config::default()).unwrap();
        let mut profile_rx = Profile6::new(Profile6Config::default()).unwrap();
        let mut data = vec![0x00; 8];
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_tx.read_counter(&data), 0);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
    }

    #[test]
    fn test_profile6_receiver_joining_a_running_stream_is_in_step_after_one_frame() {
        for (max_delta_counter, first) in
            [(1, E2EStatus::WrongSequence), (2, E2EStatus::OkSomeLost)]
        {
            let config = Profile6Config {
                max_delta_counter,
                ..Default::default()
            };
            let mut profile_tx = Profile6::new(config.clone()).unwrap();
            let mut profile_rx = Profile6::new(config).unwrap();
            profile_tx.set_counter(1).unwrap();
            let mut data = vec![0x00; 8];
            profile_tx.protect(&mut data).unwrap();
            assert_eq!(profile_rx.check(&data).unwrap(), first);
            profile_tx.protect(&mut data).unwrap();
            assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        }
    }

    #[test]
    fn test_profile6_header_offset_past_the_maximum_length_is_refused() {
        for offset in [4, 480] {
            let config = Profile6Config {
                offset,
                max_data_length: 64 * 8,
                ..Default::default()
            };
            assert!(
                matches!(
                    Profile6::new(config),
                    Err(E2EError::InvalidConfiguration(_))
                ),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn test_profile6_header_offset_past_the_frame_is_refused() {
        let config = Profile6Config {
            offset: 64,
            max_data_length: 64 * 8,
            ..Default::default()
        };
        let mut profile_tx = Profile6::new(config.clone()).unwrap();
        let mut profile_rx = Profile6::new(config).unwrap();

        let mut data = vec![0x00; 64];
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);

        let mut short = vec![0x00; 5];
        assert!(matches!(
            profile_tx.protect(&mut short),
            Err(E2EError::InvalidDataFormat(_))
        ));
        assert!(matches!(
            profile_rx.check(&short),
            Err(E2EError::InvalidDataFormat(_))
        ));
    }
}
