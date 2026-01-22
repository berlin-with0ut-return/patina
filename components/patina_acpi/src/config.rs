//! Patina ACPI Component Configuration
//!
//! ## ACPI Component Configuration Usage
//!
//! The configuration can be set statically with `.with_config()` or produced dynamically during boot.
//!
//! ## Static Configuration Example
//!
//! ```rust,ignore
//! // ...
//! impl ComponentInfo for Q35 {
//!     fn configs(mut add: Add<Config>) {
//!        add.config(patina_acpi::config::AcpiConfig { enable_component: true });
//!    }
//! }
//!
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use patina::component::params::ConfigMut;

use crate::hob::AcpiConfigHob;
use patina::component::{
    component,
    hob::{FromHob, Hob},
};

/// Default: component disabled unless explicitly enabled by platform/HOB.
pub const DEFAULT_ENABLE_COMPONENT: bool = false;

/// The configuration for the Patina ACPI component.
#[derive(Debug, Clone, Copy)]
pub struct AcpiConfig {
    /// Indicates whether the Patina ACPI component is enabled.
    pub enable_component: bool,
}

impl Default for AcpiConfig {
    fn default() -> AcpiConfig {
        Self { enable_component: DEFAULT_ENABLE_COMPONENT }
    }
}

struct AcpiConfigProvider;

#[component]
impl AcpiConfigProvider {
    /// Entry point for the Patina ACPI Configuration Provider.
    ///
    /// ## Parameters
    ///
    /// - `acpi_config_hob`: A HOB that contains platform configuration for the Patina ACPI component.
    /// - `config_mut`: A mutable reference to the Patina ACPI Config instance to be populated with runtime
    ///   information.
    ///
    /// ## Returns
    ///
    /// - `Ok(())` if the entry point was successful.
    /// - `Err(patina::error::Result)` if the entry point failed.
    ///
    pub fn entry_point(
        self,
        acpi_config_hob: Hob<AcpiConfigHob>,
        mut config_mut: ConfigMut<AcpiConfig>,
    ) -> patina::error::Result<()> {
        log::trace!("Patina ACPI Configuration Provider Entry Point");

        log::trace!("Incoming Patina ACPI Component Configuration: {:?}", *config_mut);

        config_mut.enable_component = acpi_config_hob.enable_component != 0;
        if !config_mut.enable_component {
            log::trace!("The Patina ACPI component is disabled per HOB configuration.");
        } else {
            log::trace!("The Patina ACPI component is enabled per HOB configuration.");
        }

        log::trace!("Outgoing ACPI Configuration: {:?}", *config_mut);

        config_mut.lock();

        Ok(())
    }
}
