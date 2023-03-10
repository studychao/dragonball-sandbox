// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.

//![deny(missing_docs)]

//! Implements PCI devices and buses.
//!
//! The role and relationship about PCI related traits/structs:
//! - PCI root: a pseudo device to handle PCI configuration accesses.
//! - PCI bus: a container object to hold PCI devices and resources, corresponding to the PCI bus
//!   defined in PCI/PCIe specs.
//! - PCI root bus: a special PCI bus which has no parent PCI bus. The device 0 under PCI root bus
//!   represent the root bus itself.
//! - PCI device: the real object to emulate a PCI device. For most PCI devices, it needs to
//!   handle accesses to PCI configuration space and PCI BARs.
//! - PCI configuration: a common framework to emulator PCI configuration space header.
//! - PCI MSI/MSIx: structs to emulate PCI MSI/MSIx capabilities.

#[macro_use]
extern crate log;
extern crate vm_device;
extern crate vm_memory;
extern crate vmm_sys_util;

use std::fmt::Display;
use std::sync::Arc;

use vm_device::{device_manager::IoManagerContext, interrupt::KvmIrqManager};

mod bus;
pub use self::bus::PciBus;

mod configuration;
pub use self::configuration::{
    BarProgrammingParams, PciBarConfiguration, PciBarPrefetchable, PciBarRegionType,
    PciBridgeSubclass, PciCapability, PciCapabilityID, PciClassCode, PciConfiguration,
    PciHeaderType, PciInterruptPin, PciMassStorageSubclass, PciMultimediaSubclass,
    PciNetworkControllerSubclass, PciProgrammingInterface, PciSerialBusSubClass, PciSubclass,
    NUM_BAR_REGS, NUM_CONFIGURATION_REGISTERS,
};

mod device;
pub use self::device::PciDevice;
#[cfg(target_arch = "aarch64")]
pub use self::device::{PciBusResources, ECAM_SPACE_LENGTH};

mod msi;
pub use self::msi::{MsiCap, MsiState};

mod msix;
pub use self::msix::{
    MsixCap, MsixState, MsixTableEntry, FUNCTION_MASK_MASK, MSIX_ENABLE_MASK,
    MSIX_TABLE_ENTRIES_MODULO, MSIX_TABLE_ENTRY_SIZE,
};

mod root_bus;
pub use self::root_bus::create_pci_root_bus;

mod root_device;
pub use self::root_device::PciRootDevice;

#[cfg(feature = "vm-snapshot")]
pub mod persist {
    pub use super::bus::persist::PciBusState;
    pub use super::configuration::persist::{
        PciConfigurationState, PciConfigurationStateConstructorArgs,
    };
    pub use super::msi::persist::{MsiCapState, MsiCapStateConstructorArgs, MsiStatePersistState};
    pub use super::msix::persist::MsixCapState;
    pub use super::root_device::persist::{PciRootContentConstructorArgs, PciRootDeviceState};
}
#[cfg(feature = "vm-snapshot")]
pub mod version_manager;

/// Error codes related to PCI root/bus/device operations.
#[derive(Debug)]
pub enum Error {
    /// Failed to activate the PCI root/bus/device.
    ActivateFailure(vm_device::device_manager::Error),
    /// Invalid bus id
    InvalidBusId(u8),
    /// Invalid resource assigned/allocated.
    InvalidResource(vm_device::resources::Resource),
    /// Errors from IoManager
    IoManager(vm_device::device_manager::Error),
    /// No resources available.
    NoResources,
    /// PCI BAR is already in use.
    BarInUse(usize),
    /// PCI BAR is invalid.
    BarInvalid(usize),
    /// PCI BAR size is invalid.
    BarSizeInvalid(u64),
    /// PCI BAR address is invalid.
    BarAddressInvalid(u64, u64),
    /// 64 bits MMIO PCI BAR is invalid.
    BarInvalid64(usize),
    /// 64 bits MMIO PCI BAR is in use.
    BarInUse64(usize),
    /// PCI ROM BAR is invalid.
    RomBarInvalid(usize),
    /// PCI ROM BAR is already in use.
    RomBarInUse(usize),
    /// PCI ROM BAR size is invalid.
    RomBarSizeInvalid(u64),
    /// PCI ROM BAR address is invalid.
    RomBarAddressInvalid(u64, u64),
    /// Zero sized PCI capability
    CapabilityEmpty,
    /// No space available for new PCI capability.
    CapabilitySpaceFull(usize),
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::Error::*;
        match self {
            ActivateFailure(e) => write!(f, "failed to activate PCI device, {:?}", e),
            InvalidBusId(b) => write!(f, "bus id {} invalid", b),
            InvalidResource(_) => write!(f, "invalid resource"),
            IoManager(e) => write!(f, "{:?}", e),
            NoResources => write!(f, "no resources available"),
            BarInUse(b) => write!(f, "bar {} already used", b),
            BarInvalid(b) => write!(f, "bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            BarSizeInvalid(s) => write!(f, "bar address {} not a power of two", s),
            BarAddressInvalid(a, s) => write!(f, "address {} size {} too big", a, s),
            BarInvalid64(b) => write!(
                f,
                "64bitbar {} invalid, requires two regs, max {}",
                b,
                NUM_BAR_REGS - 1
            ),
            BarInUse64(b) => write!(f, "64bit bar {} already used(requires two regs)", b),
            RomBarInUse(b) => write!(f, "rom bar {} already used", b),
            RomBarInvalid(b) => write!(f, "rom bar {} invalid, max {}", b, NUM_BAR_REGS - 1),
            RomBarSizeInvalid(s) => write!(f, "rom bar address {} not a power of two", s),
            RomBarAddressInvalid(a, s) => write!(f, "address {} size {} too big", a, s),
            CapabilityEmpty => write!(f, "empty capabilities are invalid"),
            CapabilitySpaceFull(s) => write!(f, "capability of size {} doesn't fit", s),
        }
    }
}

/// Specialized `Result` for PCI related operations.
pub type Result<T> = std::result::Result<T, Error>;

pub trait PciSystemContext: Sync + Send + Clone {
    type D: IoManagerContext + Send + Sync + Clone;

    fn get_device_manager_context(&self) -> Self::D;

    fn get_interrupt_manager(&self) -> Arc<KvmIrqManager>;
}

/// Fill the buffer with all bits set for invalid PCI configuration space access.
pub fn fill_config_data(data: &mut [u8]) {
    // Return data with all bits set.
    for pos in data.iter_mut() {
        *pos = 0xff;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    /*
    use super::*;
    use std::sync::Arc;
    use vm_device::interrupt::{InterruptSourceGroup, InterruptSourceType};
    use vm_device::resources::Resource;
    use vm_device::DeviceIo;

    #[derive(Clone)]
    pub struct PciInterruptManager {}

    impl InterruptManager for PciInterruptManager {
        fn create_group(
            &self,
            type_: InterruptSourceType,
            base: u32,
            count: u32,
        ) -> std::result::Result<Arc<Box<dyn InterruptSourceGroup>>, std::io::Error> {
            unimplemented!()
        }

        fn destroy_group(
            &self,
            group: Arc<Box<InterruptSourceGroup>>,
        ) -> std::result::Result<(), std::io::Error> {
            unimplemented!()
        }
    }

    #[derive(Clone)]
    pub struct PciIoManagerContext {}

    impl IoManagerContext for PciIoManagerContext {
        type Context = ();

        fn begin_tx(&self) -> Self::Context {
            unimplemented!()
        }

        fn commit_tx(&self, context: Self::Context) {
            unimplemented!()
        }

        fn cancel_tx(&self, context: Self::Context) {
            unimplemented!()
        }

        fn register_device_io(
            &self,
            ctx: &mut Self::Context,
            device: Arc<DeviceIo>,
            resources: &[Resource],
        ) -> std::result::Result<(), vm_device::device_manager::Error> {
            unimplemented!()
        }

        fn unregister_device_io(
            &self,
            ctx: &mut Self::Context,
            resources: &[Resource],
        ) -> std::result::Result<(), vm_device::device_manager::Error> {
            unimplemented!()
        }
    }

    #[derive(Clone, Default)]
    pub struct SystemContext {}

    impl PciSystemContext for SystemContext {
        type I = PciInterruptManager;
        type D = PciIoManagerContext;

        fn get_device_manager_context(&self) -> Self::D {
            unimplemented!()
        }

        fn get_interrupt_manager(&self) -> Self::I {
            unimplemented!()
        }
    }
    */
}
