//! ACPI Service Definitions.
//!
//! Defines the ACPI Provider for use as a service.
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use core::any::TypeId;

use alloc::vec::Vec;
use patina::component::service::{IntoService, Service, memory::MemoryManager};
use r_efi::efi;

use crate::{
    acpi_table::{AcpiTable, AcpiTableHeader, Table},
    error::AcpiError,
    service::mm::AcpiMM,
};

#[cfg(any(test, feature = "mockall"))]
use mockall::automock;

/// Represents an opaque reference to an installed ACPI table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableKey(pub(crate) usize);

/// A notification function that is called when a new ACPI table is installed.
pub type AcpiNotifyFn = fn(
    &AcpiTableHeader, /* Standard ACPI header. */
    u32,              /* Supported ACPI versions. */
    usize,            /* Table key. */
) -> efi::Status;

/// The `AcpiTableManager` provides functionality for installing, uninstalling, and accessing ACPI tables.
/// This struct serves as the API by which internal implementations can provide custom ACPI implementation.
#[cfg_attr(any(test, feature = "mockall"), automock)]
pub(crate) trait AcpiProvider {
    /// Installs an ACPI table and returns an associated key which can be used to get or uninstall the table later.
    fn install_acpi_table_generic(&self, acpi_table: Table) -> Result<TableKey, AcpiError>;

    /// Uninstalls an ACPI table using the same `table_key` returned at the time of installation.
    fn uninstall_acpi_table(&self, table_key: TableKey) -> Result<(), AcpiError>;

    /// Retrieves an ACPI table by its table key. This must be the same key returned at the time of installation.
    fn get_acpi_table_generic(&self, table_key: TableKey) -> Result<AcpiTable, AcpiError>;

    /// Registers or unregisters a function which will be called whenever a new ACPI table is installed.
    fn register_notify(&self, should_register: bool, notify_fn: AcpiNotifyFn) -> Result<(), AcpiError>;

    /// Returns all currently installed tables in an iterable format.
    fn collect_tables(&self) -> Vec<AcpiTable>;
}

pub(crate) trait AcpiProviderExt {
    unsafe fn install_acpi_table<T: 'static>(&self, table: T) -> Result<TableKey, AcpiError>;
    fn get_acpi_table<T: Clone + 'static>(&self, table_key: TableKey) -> Result<T, AcpiError>;
    unsafe fn get_acpi_table_unchecked<T: 'static>(&self, table_key: TableKey) -> Result<&T, AcpiError>;
}

impl AcpiProviderExt for Service<dyn AcpiProvider> {
    unsafe fn install_acpi_table<T: 'static>(&self, table: T) -> Result<TableKey, AcpiError> {
        // SAFETY: If the safety contract of this function is upheld, the created AcpiTable is valid.
        let acpi_table = unsafe { Table::new(table)? };
        self.install_acpi_table_generic(acpi_table)
    }

    fn get_acpi_table<T: Clone + 'static>(&self, table_key: TableKey) -> Result<T, AcpiError> {
        let acpi_table = self.get_acpi_table_generic(table_key)?;

        // There may be ACPI tables whose type is unknown at installation, due to installation from the HOB or a C protocol.
        // In these cases, the type is is unspecified (AcpiTableHeader instead of a specific table type), so we skip type checking.
        // In all other cases, verify the type provided by the user is valid.
        if acpi_table.type_id != TypeId::of::<T>() {
            return Err(AcpiError::InvalidTableType);
        }

        // SAFETY: The type id of the returned table has been verified.
        // SAFETY: The installed tables are stored in the provider and live at least as long as `self`,
        // Cast the table to its expected type.
        unsafe { Ok(acpi_table.as_ref::<T>().clone()) }
    }

    unsafe fn get_acpi_table_unchecked<T: 'static>(&self, table_key: TableKey) -> Result<&T, AcpiError> {
        let acpi_table = self.get_acpi_table_generic(table_key)?;

        // Cast the table to its expected type.
        let raw_table_ptr: *const T = acpi_table.table.cast::<T>().as_ptr();

        // SAFETY: The installed tables are stored in the provider and live at least as long as `self`.
        Ok(unsafe { &*raw_table_ptr })
    }
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use alloc::boxed::Box;
    use patina::component::service::memory::StdMemoryManager;

    use crate::acpi_table::AcpiFadt;

    use super::*;

    #[test]
    fn test_get_table_wrong_type() {
        // Allow Send and Sync for AcpiTable in this test context.
        #[allow(non_local_definitions)]
        // SAFETY: This is only for testing purposes.
        unsafe impl Send for AcpiTable {}
        #[allow(non_local_definitions)]
        // SAFETY: This is only for testing purposes.
        unsafe impl Sync for AcpiTable {}

        // SAFETY: The constructed table is a valid ACPI table.
        let table = unsafe {
            AcpiTable::new(
                AcpiFadt { header: AcpiTableHeader { length: 245, ..Default::default() }, ..Default::default() },
                &Service::mock(Box::new(StdMemoryManager::new())),
            )
            .unwrap()
        };

        let mut mock_acpi_provider = MockAcpiProvider::new();
        mock_acpi_provider.expect_get_acpi_table().returning(move |_table_key| Ok(table));
        let provider = AcpiTableManager {
            provider_service: Service::mock(Box::new(mock_acpi_provider)),
            memory_manager: Service::mock(Box::new(StdMemoryManager::new())),
        };

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct TestTable;

        let result = provider.get_acpi_table::<TestTable>(TableKey(0));
        assert_eq!(result, Err(AcpiError::InvalidTableType));
    }
}
