//! ACPI Constants.
//!
//! Defines common constants and table signatures for the ACPI service interface.
//! The following definitions only support ACPI 2.0+.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0

use core::mem;

use patina::signature;
use r_efi::efi;

use crate::acpi_table::{AcpiDsdt, AcpiFacs, AcpiFadt, AcpiTableHeader};

// Helpers for handling ACPI signatures

pub const FACS: u32 = signature!('F', 'A', 'C', 'S');
pub const UEFI: u32 = signature!('U', 'E', 'F', 'I');
pub const FACP: u32 = signature!('F', 'A', 'C', 'P');
pub const DSDT: u32 = signature!('D', 'S', 'D', 'T');
pub const XSDT: u32 = signature!('X', 'S', 'D', 'T');
pub const FADT: u32 = FACP; // For legacy ACPI reasons, the FADT has signature 'FACP'.
pub const MADT: u32 = signature!('M', 'A', 'D', 'T');
pub const HPET: u32 = signature!('H', 'P', 'E', 'T');
pub const MCFG: u32 = signature!('M', 'C', 'F', 'G');
pub const BGRT: u32 = signature!('B', 'G', 'R', 'T');

pub const ACPI_TABLE_GUID: efi::Guid =
    efi::Guid::from_fields(0x8868E871, 0xE4F1, 0x11D3, 0xBC, 0x22, &[0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81]);

pub(crate) const ACPI_HEADER_LEN: usize = mem::size_of::<AcpiTableHeader>();
pub(crate) const MAX_INITIAL_ENTRIES: usize = 32;
pub(crate) const ACPI_CHECKSUM_OFFSET: usize = memoffset::offset_of!(AcpiTableHeader, checksum);

pub const ACPI_RSDP_TABLE: u64 = signature!('R', 'S', 'D', ' ', 'P', 'T', 'R', ' ');
pub const ACPI_RSDP_REVISION: u8 = 2;

pub const ACPI_XSDT_REVISION: u8 = 1;
pub(crate) const ACPI_XSDT_ENTRY_SIZE: usize = core::mem::size_of::<u64>();

pub const ACPI_RESERVED_BYTE: u8 = 0x00;

/// Bitmask indicating versions support of all ACPI versions 2.0+.
pub const ACPI_VERSIONS_GTE_2: u32 = (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5);

// Sizing information for known ACPI table formats.
// Note that for many these are minimum sizes since many tables contain a variable-length portion at the end.
pub const FADT_SIZE: usize = mem::size_of::<AcpiFadt>();
pub const FACS_SIZE: usize = mem::size_of::<AcpiFacs>();
pub const DSDT_SIZE: usize = mem::size_of::<AcpiDsdt>();
pub const MADT_SIZE: usize = 44;
pub const HPET_SIZE: usize = 56;
pub const MCFG_SIZE: usize = 44;
pub const BGRT_SIZE: usize = 56;

pub fn acpi_table_min_size(signature: u32) -> usize {
    match signature {
        FACS => FACS_SIZE,
        FACP => FADT_SIZE,
        DSDT => DSDT_SIZE,
        MADT => MADT_SIZE,
        HPET => HPET_SIZE,
        MCFG => MCFG_SIZE,
        BGRT => BGRT_SIZE,
        _ => ACPI_HEADER_LEN, // Default to the header size for unknown signatures, or tables without additional size information.
    }
}
