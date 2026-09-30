//! # E2E Profile 1 Implementation
//!
//! Profile 1 is the legacy predecessor of Profile 11 and is bus-compatible with it
//! in the `Both` and `Nibble` modes. It uses:
//! - 8-bit CRC (CRC-8-SAE J1850, start and XOR value 0x00) for data integrity
//! - 4-bit counter for sequence checking (0-14, 0xF is never sent)
//! - 16-bit Data ID folded into the CRC in one of four modes
//!
//! # Data layout
//! [DATA ... | CRC(1B) | HDR(1B) | DATA ...]
//! - HDR (bits 7..4) : DI_hi_nibble(nibble mode) OR data(other modes)
//! - HDR (bits 3..0) : counter
//!
//! # Modes
//!
//! - **Both(1A)**: both Data ID bytes, low then high, go into the CRC.
//! - **Alt**: the low byte on even counters, the high byte on odd counters.
//! - **Low**: only the low byte goes into the CRC.
//! - **Nibble(1C)**: the low byte and a zero byte go into the CRC; the low nibble of
//!   the high byte is sent in the header.

use crate::{E2EError, E2EProfile, E2EResult, E2EStatus};
use crc::{Algorithm, Crc};

// Constants
const NIBBLE_MASK: u8 = 0x0F;
const COUNTER_MAX: u8 = 14;
const COUNTER_MODULO: u8 = 15;
const MAX_DATA_LENGTH_BITS: u8 = 240;
const BITS_PER_BYTE: u8 = 8;
const BITS_PER_NIBBLE: u8 = 4;

// Profile 1 uses CRC-8-SAE J1850 with start and XOR value 0x00
const CRC8_ALGO: Algorithm<u8> = Algorithm {
    width: 8,
    poly: 0x1d,
    init: 0x00,
    refin: false,
    refout: false,
    xorout: 0x00,
    check: 0x37,
    residue: 0x00,
};

/// Data-ID mode for Profile 1.
///
/// # Variants
///
/// * `Both` - Profile 1A: both bytes of the 16-bit Data-ID go into the CRC,
///   low byte first.
///
/// * `Alt` - The low byte goes into the CRC when the counter is even, the
///   high byte when it is odd.
///
/// * `Low` - Only the low byte goes into the CRC; the high byte is ignored.
///
/// * `Nibble` - Profile 1C: the low byte and a zero byte go into the CRC, and
///   the low nibble of the high byte is sent in the header. Only the lower 12
///   bits of the Data-ID are used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile1IdMode {
    Both,
    Alt,
    Low,
    Nibble,
}

/// Configuration for E2E Profile 1
#[derive(Debug, Clone)]
pub struct Profile1Config {
    /// Bit offset of Counter in MSB first order
    pub counter_offset: u8,
    /// Bit offset of CRC in MSB first order
    pub crc_offset: u8,
    /// Data-ID mode
    pub mode: Profile1IdMode,
    /// A unique identifier
    pub data_id: u16,
    /// Bit offset of the low nibble of the high byte of Data ID
    pub nibble_offset: u8,
    /// Maximum allowed delta between consecutive counters
    pub max_delta_counter: u8,
    /// data length (up to MAX_DATA_LENGTH_BITS bits)
    pub data_length: u8,
}

impl Default for Profile1Config {
    fn default() -> Self {
        Self {
            counter_offset: 8, // bits
            crc_offset: 0,     // bits
            mode: Profile1IdMode::Both,
            data_id: 0x123,
            nibble_offset: 12, // bits
            max_delta_counter: 1,
            data_length: 64, // bits
        }
    }
}

pub struct Profile1Check {
    rx_counter: u8,
    rx_crc: u8,
    rx_nibble: u8,
    calculated_crc: u8,
}
/// E2E Profile 1 Implementation
///
/// Implements AUTOSAR E2E Profile 1 protection mechanism with all four
/// Data-ID modes.
#[derive(Clone)]
pub struct Profile1 {
    config: Profile1Config,
    counter: u8,
    initialized: bool,
}

impl Profile1 {
    /// Validate configuration parameters
    fn validate_config(config: &Profile1Config) -> E2EResult<()> {
        if config.data_length > MAX_DATA_LENGTH_BITS {
            return Err(E2EError::InvalidConfiguration(format!(
                "Maximum data length for Profile 1 is {} bits",
                MAX_DATA_LENGTH_BITS
            )));
        }

        if !config.data_length.is_multiple_of(BITS_PER_BYTE) {
            return Err(E2EError::InvalidConfiguration(
                "Data length shall be a multiple of 8".into(),
            ));
        }

        // The CRC byte and the counter nibble, in whole bytes.
        if config.data_length < 2 * BITS_PER_BYTE {
            return Err(E2EError::InvalidConfiguration(
                "Data length shall hold the CRC and the counter, at least 16 bits".into(),
            ));
        }

        if config.max_delta_counter == 0 || config.max_delta_counter > COUNTER_MAX {
            return Err(E2EError::InvalidConfiguration(format!(
                "Max delta counter must be between 1 and {}",
                COUNTER_MAX
            )));
        }

        if !config.counter_offset.is_multiple_of(BITS_PER_NIBBLE) {
            return Err(E2EError::InvalidConfiguration(
                "Counter offset shall be a multiple of 4".into(),
            ));
        }

        if !config.crc_offset.is_multiple_of(BITS_PER_BYTE) {
            return Err(E2EError::InvalidConfiguration(
                "Crc offset shall be a multiple of 8".into(),
            ));
        }

        if config.mode == Profile1IdMode::Nibble
            && !config.nibble_offset.is_multiple_of(BITS_PER_NIBBLE)
        {
            return Err(E2EError::InvalidConfiguration(
                "Nibble offset must be a multiple of 4 bits".into(),
            ));
        }

        // Each field lies wholly within the data, which also rules out data too short for the CRC
        // byte and the counter nibble.
        let fits = |offset: u8, bits: u8| {
            u16::from(offset) + u16::from(bits) <= u16::from(config.data_length)
        };
        if !fits(config.counter_offset, BITS_PER_NIBBLE)
            || !fits(config.crc_offset, BITS_PER_BYTE)
            || (config.mode == Profile1IdMode::Nibble
                && !fits(config.nibble_offset, BITS_PER_NIBBLE))
        {
            return Err(E2EError::InvalidConfiguration(
                "Offsets shall lie within the data length".into(),
            ));
        }

        Ok(())
    }
    /// Validate data length against the configured length
    fn validate_length(&self, len: usize) -> E2EResult<()> {
        let expected_bytes = (self.config.data_length / BITS_PER_BYTE) as usize;
        if len != expected_bytes {
            return Err(E2EError::InvalidDataFormat(format!(
                "Expected {} bytes, got {} bytes",
                expected_bytes, len
            )));
        }
        Ok(())
    }
    fn write_nibble_data(&self, offset: u8, set_value: u8, data: &mut [u8]) {
        let byte_idx = (offset >> 3) as usize;
        let shift = offset & 0x07;

        let mask = !(NIBBLE_MASK << shift);
        let val = (set_value & NIBBLE_MASK) << shift;
        data[byte_idx] = (data[byte_idx] & mask) | val;
    }
    fn read_nibble_data(&self, offset: u8, data: &[u8]) -> u8 {
        let byte_idx = (offset >> 3) as usize;
        let shift = offset & 0x07;

        (data[byte_idx] >> shift) & NIBBLE_MASK
    }
    fn write_crc(&self, calculated_crc: u8, data: &mut [u8]) {
        let byte_position = (self.config.crc_offset / BITS_PER_BYTE) as usize;
        data[byte_position] = calculated_crc;
    }
    fn read_crc(&self, data: &[u8]) -> u8 {
        let byte_position = (self.config.crc_offset / BITS_PER_BYTE) as usize;
        data[byte_position]
    }
    /// Update Crc with ID
    fn update_crc_with_id(&self, digest: &mut crc::Digest<u8>, counter: u8) {
        let [low, high] = self.config.data_id.to_le_bytes();
        match self.config.mode {
            Profile1IdMode::Both => digest.update(&[low, high]),
            Profile1IdMode::Alt if counter.is_multiple_of(2) => digest.update(&[low]),
            Profile1IdMode::Alt => digest.update(&[high]),
            Profile1IdMode::Low => digest.update(&[low]),
            Profile1IdMode::Nibble => digest.update(&[low, 0x00]),
        }
    }
    fn update_crc_with_data(&self, digest: &mut crc::Digest<u8>, data: &[u8]) {
        let offset_byte = (self.config.crc_offset / BITS_PER_BYTE) as usize;
        digest.update(&data[..offset_byte]);
        digest.update(&data[(offset_byte + 1)..]);
    }
    fn compute_crc(&self, data: &[u8], counter: u8) -> u8 {
        let crc: Crc<u8> = Crc::<u8>::new(&CRC8_ALGO);
        let mut digest = crc.digest();
        self.update_crc_with_id(&mut digest, counter);
        self.update_crc_with_data(&mut digest, data);
        digest.finalize()
    }
    fn increment_counter(&mut self) {
        self.counter = (self.counter + 1) % COUNTER_MODULO;
    }
    fn do_checks(&mut self, check_items: Profile1Check) -> E2EStatus {
        if check_items.calculated_crc != check_items.rx_crc {
            return E2EStatus::CrcError;
        }
        if (self.config.mode == Profile1IdMode::Nibble)
            && ((self.config.data_id >> BITS_PER_BYTE) as u8 & NIBBLE_MASK) != check_items.rx_nibble
        {
            return E2EStatus::DataIdError;
        }
        if check_items.rx_counter > COUNTER_MAX {
            return E2EStatus::WrongSequence;
        }
        let status = self.validate_counter(check_items.rx_counter);
        self.counter = check_items.rx_counter;
        status
    }
    /// Check if counter delta is within acceptable range
    fn check_counter_delta(&self, received_counter: u8) -> u8 {
        if received_counter >= self.counter {
            received_counter - self.counter
        } else {
            // Handle wrap-around
            (COUNTER_MODULO + received_counter - self.counter) % COUNTER_MODULO
        }
    }
    fn validate_counter(&self, rx_counter: u8) -> E2EStatus {
        let delta = self.check_counter_delta(rx_counter);

        if delta == 0 {
            if self.initialized {
                E2EStatus::Repeated
            } else {
                E2EStatus::Ok
            }
        } else if delta == 1 {
            E2EStatus::Ok
        } else if delta >= 2 && delta <= self.config.max_delta_counter {
            E2EStatus::OkSomeLost
        } else {
            E2EStatus::WrongSequence
        }
    }
}

impl E2EProfile for Profile1 {
    type Config = Profile1Config;

    fn new(config: Self::Config) -> E2EResult<Self> {
        // Validate config
        Self::validate_config(&config)?;
        Ok(Self {
            config,
            counter: 0,
            initialized: false,
        })
    }

    fn protect(&mut self, data: &mut [u8]) -> E2EResult<()> {
        self.validate_length(data.len())?;
        if self.config.mode == Profile1IdMode::Nibble {
            self.write_nibble_data(
                self.config.nibble_offset,
                self.config.data_id.to_le_bytes()[1],
                data,
            );
        }
        self.write_nibble_data(self.config.counter_offset, self.counter, data);
        let calculated_crc = self.compute_crc(data, self.counter);
        self.write_crc(calculated_crc, data);
        self.increment_counter();
        Ok(())
    }

    fn check(&mut self, data: &[u8]) -> E2EResult<E2EStatus> {
        // Check data length
        self.validate_length(data.len())?;
        let rx_counter = self.read_nibble_data(self.config.counter_offset, data);
        let check_items = Profile1Check {
            // Only Nibble mode sends the Data-ID nibble, so only it has an offset that was checked.
            rx_nibble: if self.config.mode == Profile1IdMode::Nibble {
                self.read_nibble_data(self.config.nibble_offset, data)
            } else {
                0
            },
            rx_counter,
            rx_crc: self.read_crc(data),
            calculated_crc: self.compute_crc(data, rx_counter),
        };
        let status = self.do_checks(check_items);
        if !self.initialized && matches!(status, E2EStatus::Ok | E2EStatus::OkSomeLost) {
            self.initialized = true;
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile11::{Profile11, Profile11Config, Profile11IdMode};

    fn config(mode: Profile1IdMode) -> Profile1Config {
        Profile1Config {
            mode,
            data_id: 0x1234,
            ..Default::default()
        }
    }

    #[test]
    fn test_profile1_nibble_offset_outside_the_data_is_ignored_unless_nibble_mode() {
        let config = Profile1Config {
            mode: Profile1IdMode::Both,
            data_length: 32,
            nibble_offset: 60,
            ..Default::default()
        };
        let mut sender = Profile1::new(config.clone()).unwrap();
        let mut receiver = Profile1::new(config.clone()).unwrap();
        let mut data = [0u8; 4];
        sender.protect(&mut data).unwrap();
        assert_eq!(receiver.check(&data).unwrap(), E2EStatus::Ok);

        let nibble = Profile1Config {
            mode: Profile1IdMode::Nibble,
            ..config
        };
        assert!(Profile1::new(nibble).is_err());
    }

    #[test]
    fn test_profile1_data_too_short_for_its_fields_is_refused() {
        for data_length in [0, 8] {
            let config = Profile1Config {
                data_length,
                crc_offset: 0,
                counter_offset: 0,
                ..Default::default()
            };
            assert!(Profile1::new(config).is_err(), "{data_length} bits");
        }
    }

    #[test]
    fn test_profile1_crc_vectors() {
        // CRC over data_id (low, high) followed by the data, as in mode Both.
        let vectors: &[(u16, &[u8], u8)] = &[
            (0x0000, &[], 0x00),
            (0x0000, &[0xFF], 0xC4),
            (0x0000, &[0x01, 0x02, 0x03], 0x30),
            (0x1234, &[], 0x1B),
            (0x1234, &[0x01, 0x02, 0x03], 0xA8),
            (0xFFFF, &[0x01, 0x02, 0x03], 0x79),
            (0xA5A5, &[0x01, 0x23, 0x45, 0x67, 0x89], 0xF7),
        ];
        let crc = Crc::<u8>::new(&CRC8_ALGO);
        for (data_id, data, expected) in vectors {
            let mut digest = crc.digest();
            digest.update(&data_id.to_le_bytes());
            digest.update(data);
            assert_eq!(digest.finalize(), *expected, "data_id {data_id:#06x}");
        }
        assert_eq!(crc.checksum(b"123456789"), CRC8_ALGO.check);
    }

    #[test]
    fn test_profile1_basic_both_example() {
        let config = Profile1Config {
            data_length: 32,
            ..config(Profile1IdMode::Both)
        };
        let mut profile_tx = Profile1::new(config.clone()).unwrap();
        let mut profile_rx = Profile1::new(config).unwrap();

        let mut data = vec![0x00, 0x00, 0x02, 0x03];
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        profile_tx.protect(&mut data).unwrap();
        // CRC over 0x34 0x12 0x01 0x02 0x03
        assert_eq!(data, [0xa8, 0x01, 0x02, 0x03]);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
    }

    #[test]
    fn test_profile1_round_trip_in_every_mode() {
        for mode in [
            Profile1IdMode::Both,
            Profile1IdMode::Alt,
            Profile1IdMode::Low,
            Profile1IdMode::Nibble,
        ] {
            let mut profile_tx = Profile1::new(config(mode)).unwrap();
            let mut profile_rx = Profile1::new(config(mode)).unwrap();
            for i in 0..32u8 {
                let mut data = vec![0x00, 0x00, 0xCA, 0xF1, 0x00, 0x80, 0x00, 0xFC];
                profile_tx.protect(&mut data).unwrap();
                assert_eq!(data[1] & NIBBLE_MASK, i % COUNTER_MODULO);
                assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok, "{mode:?}");
            }
        }
    }

    #[test]
    fn test_profile1_nibble_mode_sends_the_high_nibble() {
        let mut profile_tx = Profile1::new(config(Profile1IdMode::Nibble)).unwrap();
        let mut data = vec![0x00; 8];
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(data[1] >> 4, 0x2);
    }

    #[test]
    fn test_profile1_other_modes_keep_the_high_nibble() {
        for mode in [
            Profile1IdMode::Both,
            Profile1IdMode::Alt,
            Profile1IdMode::Low,
        ] {
            let mut profile_tx = Profile1::new(config(mode)).unwrap();
            let mut data = vec![0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            profile_tx.protect(&mut data).unwrap();
            assert_eq!(data[1] >> 4, 0xA, "{mode:?}");
        }
    }

    #[test]
    fn test_profile1_alt_mode_uses_one_byte_per_counter() {
        let low_only = Profile1Config {
            data_id: 0x0034,
            ..config(Profile1IdMode::Low)
        };
        let high_only = Profile1Config {
            data_id: 0x0012,
            ..config(Profile1IdMode::Low)
        };
        let mut alt = Profile1::new(config(Profile1IdMode::Alt)).unwrap();
        let mut low = Profile1::new(low_only).unwrap();
        let mut high = Profile1::new(high_only).unwrap();
        for counter in 0..4u8 {
            let mut data_alt = vec![0x00, 0x00, 1, 2, 3, 4, 5, 6];
            let mut data_low = data_alt.clone();
            let mut data_high = data_alt.clone();
            alt.protect(&mut data_alt).unwrap();
            low.protect(&mut data_low).unwrap();
            high.protect(&mut data_high).unwrap();
            let expected = if counter % 2 == 0 {
                &data_low
            } else {
                &data_high
            };
            assert_eq!(&data_alt, expected, "counter {counter}");
        }
    }

    #[test]
    fn test_profile1_is_bus_compatible_with_profile11() {
        for (mode1, mode11) in [
            (Profile1IdMode::Both, Profile11IdMode::Both),
            (Profile1IdMode::Nibble, Profile11IdMode::Nibble),
        ] {
            let mut p1 = Profile1::new(config(mode1)).unwrap();
            let mut p11 = Profile11::new(Profile11Config {
                mode: mode11,
                data_id: 0x1234,
                ..Default::default()
            })
            .unwrap();
            for _ in 0..16 {
                let mut data1 = vec![0x00, 0x00, 0xCA, 0xF1, 0x00, 0x80, 0x00, 0xFC];
                let mut data11 = data1.clone();
                p1.protect(&mut data1).unwrap();
                p11.protect(&mut data11).unwrap();
                assert_eq!(data1, data11, "{mode1:?}");
            }
        }
    }

    #[test]
    fn test_profile1_crc_offset() {
        let config = Profile1Config {
            crc_offset: 16,
            counter_offset: 24,
            ..config(Profile1IdMode::Both)
        };
        let mut profile_tx = Profile1::new(config.clone()).unwrap();
        let mut profile_rx = Profile1::new(config).unwrap();
        let mut data = vec![0xEE, 0xEE, 0x00, 0x00, 1, 2, 3, 4];
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(&data[..2], &[0xEE, 0xEE]);
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::Ok);
        data[7] ^= 0x01;
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::CrcError);
    }

    #[test]
    fn test_profile1_counter_statuses() {
        let config = Profile1Config {
            max_delta_counter: 3,
            ..config(Profile1IdMode::Both)
        };
        let mut profile_tx = Profile1::new(config.clone()).unwrap();
        let mut profile_rx = Profile1::new(config).unwrap();
        let mut frames = Vec::new();
        for _ in 0..15 {
            let mut data = vec![0x00; 8];
            profile_tx.protect(&mut data).unwrap();
            frames.push(data);
        }
        assert_eq!(profile_rx.check(&frames[0]).unwrap(), E2EStatus::Ok);
        assert_eq!(profile_rx.check(&frames[0]).unwrap(), E2EStatus::Repeated);
        assert_eq!(profile_rx.check(&frames[1]).unwrap(), E2EStatus::Ok);
        assert_eq!(profile_rx.check(&frames[3]).unwrap(), E2EStatus::OkSomeLost);
        assert_eq!(
            profile_rx.check(&frames[8]).unwrap(),
            E2EStatus::WrongSequence
        );
        assert_eq!(
            profile_rx.check(&frames[14]).unwrap(),
            E2EStatus::WrongSequence
        );
        // 14 -> 0 is a normal advance.
        assert_eq!(profile_rx.check(&frames[0]).unwrap(), E2EStatus::Ok);
    }

    #[test]
    fn test_profile1_counter_value_fifteen_is_refused() {
        let mut profile_rx = Profile1::new(config(Profile1IdMode::Both)).unwrap();
        let mut data = vec![0x00, 0x0F, 0, 0, 0, 0, 0, 0];
        let crc = Profile1::new(config(Profile1IdMode::Both))
            .unwrap()
            .compute_crc(&data, 0x0F);
        data[0] = crc;
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::WrongSequence);
    }

    #[test]
    fn test_profile1_nibble_mismatch() {
        let mut profile_tx = Profile1::new(config(Profile1IdMode::Nibble)).unwrap();
        let mut profile_rx = Profile1::new(Profile1Config {
            data_id: 0x0334,
            ..config(Profile1IdMode::Nibble)
        })
        .unwrap();
        let mut data = vec![0x00; 8];
        profile_tx.protect(&mut data).unwrap();
        assert_eq!(profile_rx.check(&data).unwrap(), E2EStatus::DataIdError);
    }

    #[test]
    fn test_profile1_invalid_config() {
        for config in [
            Profile1Config {
                data_length: 248,
                ..Default::default()
            },
            Profile1Config {
                data_length: 63,
                ..Default::default()
            },
            Profile1Config {
                max_delta_counter: 0,
                ..Default::default()
            },
            Profile1Config {
                max_delta_counter: 15,
                ..Default::default()
            },
            Profile1Config {
                counter_offset: 6,
                ..Default::default()
            },
            Profile1Config {
                crc_offset: 4,
                ..Default::default()
            },
            Profile1Config {
                counter_offset: 64,
                ..Default::default()
            },
        ] {
            assert!(Profile1::new(config.clone()).is_err(), "{config:?}");
        }
    }

    #[test]
    fn test_profile1_wrong_length() {
        let mut profile = Profile1::new(Profile1Config::default()).unwrap();
        let mut data = vec![0x00; 4];
        assert!(profile.protect(&mut data).is_err());
        assert!(profile.check(&data).is_err());
    }
}
