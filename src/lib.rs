//! # AUTOSAR E2E Protection Library
//!
//! This library implements the AUTOSAR E2E (End-to-End) protection mechanism
//! as specified in the AUTOSAR standard.
//!
//! ## Overview
//!
//! The E2E protection mechanism provides end-to-end data protection for
//! safety-critical automotive communication. It detects errors in data
//! transmission including:
//! - Data corruption (via CRC)
//! - Message loss, duplication, or reordering (via sequence counter)
//! - Incorrect addressing (via Data ID)
//!
//! ## Example
//!
//! ```rust
//! use autosar_e2e::{E2EProfile, E2EResult};
//! use autosar_e2e::profile11::{Profile11, Profile11Config, Profile11IdMode};
//!
//! # fn main() -> E2EResult<()> {
//! // Create a Profile 11 configuration
//! let config = Profile11Config {
//!     mode: Profile11IdMode::Nibble,
//!     max_delta_counter: 1,
//!     data_length: 40,
//!     ..Default::default()
//! };
//!
//! // Create the profile instance
//! let mut profile = Profile11::new(config)?;
//!
//! // Protect data
//! let mut data = vec![0x00, 0x00, 0x12, 0x34, 0x56]; //[CRC, counter, user data ..]
//! profile.protect(&mut data)?;
//!
//! // Check protected data
//! let status = profile.check(&data)?;
//! # Ok(())
//! # }
//! ```

use thiserror::Error;

mod profiles;
pub use profiles::profile1;
pub use profiles::profile11;
pub use profiles::profile22;
pub use profiles::profile4;
pub use profiles::profile4m;
pub use profiles::profile5;
pub use profiles::profile6;
pub use profiles::profile7;
pub use profiles::profile7m;
pub use profiles::profile8;

/// Result type for E2E operations
pub type E2EResult<T> = Result<T, E2EError>;

/// E2E Protection status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2EStatus {
    /// The checks of data in this cycle is successful
    Ok,
    /// CRC check failed - data corruption detected
    CrcError,
    /// Data ID check failed - incorrect addressing
    DataIdError,
    /// Counter check failed - same counter as previous cycle
    Repeated,
    /// Counter check failed - counter is increased within allowed configured delta
    OkSomeLost,
    /// Counter check failed - possible message loss/duplication
    WrongSequence,
    /// Data Length check failed - incorrect length
    DataLengthError,
    /// Source ID check failed - incorrect addressing
    SourceIdError,
    /// Message Type check failed
    MessageTypeError,
    /// Message Result check failed
    MessageResultError,
}

/// E2E Error types
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum E2EError {
    /// Invalid configuration provided
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Invalid data format
    #[error("Invalid data format: {0}")]
    InvalidDataFormat(String),

    /// A counter the profile never sends: beyond its width, or a value it reserves
    #[error("Invalid counter: {counter} is beyond the profile's maximum {max}")]
    InvalidCounter { counter: u32, max: u32 },
}

// Main trait for E2E Profile implementations
///
/// This trait defines the common interface that all E2E profiles must implement.
/// Each profile provides three operations:
/// - `protect`: Add E2E protection to data
/// - `set_counter`: Set the counter the next `protect` carries
/// - `check`: Verify E2E protection on received data
pub trait E2EProfile {
    /// Configuration type for this profile
    type Config;

    /// Create a new instance with the given configuration
    ///
    /// # Errors
    /// Returns `E2EError::InvalidConfiguration` if the configuration is invalid
    fn new(config: Self::Config) -> E2EResult<Self>
    where
        Self: Sized;

    /// Add E2E protection to the given data buffer
    ///
    /// This function modifies the data buffer in-place by adding:
    /// - CRC checksum
    /// - Sequence counter
    /// - Data ID (if applicable)
    ///
    /// # Arguments
    /// * `data` - Mutable reference to the data buffer to protect
    ///
    /// # Returns
    /// * `Ok(())` if protection was successfully added
    /// * `Err(E2EError)` if an error occurred
    fn protect(&mut self, data: &mut [u8]) -> E2EResult<()>;

    /// Set the counter the next `protect` carries
    ///
    /// A sender continues from a counter it did not count itself: one a forwarded payload
    /// already carries, or one the application supplied. Counting goes on from there.
    ///
    /// # Arguments
    /// * `counter` - The counter the next protected data carries
    ///
    /// # Errors
    /// Returns `E2EError::InvalidCounter` when the profile never sends `counter`: beyond its
    /// counter width, or a value it reserves, such as profile 1's 15
    fn set_counter(&mut self, counter: u32) -> E2EResult<()>;

    /// Check E2E protection on received data
    ///
    /// This function verifies the integrity of the received data by checking:
    /// - CRC checksum
    /// - Sequence counter continuity
    /// - Data ID (if applicable)
    ///
    /// # Arguments
    /// * `data` - Reference to the received data buffer
    ///
    /// # Returns
    /// * `Ok(E2EStatus)` indicating the check result
    /// * `Err(E2EError)` if an error occurred during checking
    fn check(&mut self, data: &[u8]) -> E2EResult<E2EStatus>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_status() {
        assert_eq!(E2EStatus::Ok, E2EStatus::Ok);
        assert_ne!(E2EStatus::Ok, E2EStatus::CrcError);
    }
}
