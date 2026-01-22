//! ACPI Service HOB Definitions.
//!
//! Defines HOBs (Hand-Off Blocks) used by the ACPI service interface.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use patina::component::hob::FromHob;

/// Hob that contains information about previously installed ACPI tables.
#[derive(Copy, Clone, zerocopy_derive::FromBytes, FromHob)]
#[hob = "9f9a9506-5597-4515-bab6-8bcde784ba87"]
pub struct AcpiMemoryHob {
    /// Unused fields from UNIVERSAL_PAYLOAD_GENERIC_HEADER (see https://universalscalablefirmware.github.io/documentation/2_universal_payload.html).
    /// In this ACPI implenentation, these fields are not used.
    _revision: u8,
    _reserved: u8,
    _length: u16,

    /// The address of the previous RSDP, which holds information about installed ACPI tables.
    pub rsdp_address: u64,
}

impl AcpiMemoryHob {
    /// Creates a new `AcpiMemoryHob` with the given RSDP address.
    pub fn new(rsdp_address: u64) -> Self {
        Self { _revision: 0, _reserved: 0, _length: core::mem::size_of::<AcpiMemoryHob>() as u16, rsdp_address }
    }
}

/// A HOB that contains Patina ACPI component configuration information.
#[derive(FromHob, zerocopy_derive::FromBytes)]
#[hob = "920d8462-92e2-4455-805f-84c3eda283e6"]
#[repr(C, packed)]
pub struct AcpiConfigHob {
    /// Indicates whether the Patina ACPI component is enabled.
    pub(crate) enable_component: u8,
}
