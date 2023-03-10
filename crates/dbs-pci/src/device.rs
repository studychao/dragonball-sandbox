// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::any::Any;

use downcast_rs::Downcast;
#[cfg(target_arch = "aarch64")]
use vm_device::resources::DeviceResources;
use vm_device::DeviceIo;

/// Define PCI ECAM space length
#[cfg(target_arch = "aarch64")]
pub const ECAM_SPACE_LENGTH: u64 = 0x100000;

/// PCI bus resources are used to create pci bus fdt node
#[cfg(target_arch = "aarch64")]
pub struct PciBusResources {
    /// Save the ecam space, it only contain one mmio address space
    pub ecam_space: DeviceResources,
    /// Save the bar space, it contains 2 mmio address space
    pub bar_space: DeviceResources,
}

pub trait PciDevice: DeviceIo + Send + Sync + Downcast {
    /// Get PCI device/function id on the PCI bus, which is in [0x0, 0xff].
    ///
    /// The higher 5 bits are device id and the lower 3 bits are function id.
    fn id(&self) -> u8;

    /// Write to the PCI device's configuration space.
    fn write_config(&self, offset: u32, data: &[u8]);

    /// Read from the PCI device's configuration space.
    fn read_config(&self, offset: u32, data: &mut [u8]);

    /// Provides a mutable reference to the Any trait. This is useful to let
    /// the caller have access to the underlying type behind the trait.
    fn as_any(&mut self) -> &mut dyn Any;
}

downcast_rs::impl_downcast!(PciDevice);

impl PartialEq for dyn PciDevice {
    fn eq(&self, other: &dyn PciDevice) -> bool {
        self.id() == other.id()
    }
}

/*
/// Struct to help implementing PCI device drivers.
pub struct PciDeviceState<C: PciSystemContext> {
    context: C,
    configuration: PciConfiguration,
    bar_enabled: [bool; NUM_BAR_REGS + 1],
    bar_registered: [bool; NUM_BAR_REGS + 1],
}

impl<C: PciSystemContext> PciDeviceState<C> {
    pub fn enable_bar(
        &mut self,
        bar_cfg: &PciBarConfiguration,
        device: Arc<dyn DeviceIo>,
    ) -> Result<()> {
        let bar_idx = bar_cfg.bar_index();
        if bar_idx >= self.bar_enabled.len() {
            return Err(Error::BarInvalid(bar_idx));
        }

        if self.bar_enabled[bar_idx] == false {
            self.bar_enabled[bar_idx] = true;
            let params = BarProgrammingParams {
                bar_idx,
                bar_type: bar_cfg.bar_type(),
                old_base: 0,
                new_base: bar_cfg.address(),
                len: bar_cfg.size(),
            };
            self.handle_bar_change(device, params)?;
        }

        Ok(())
    }

    pub fn disable_bar(
        &mut self,
        bar_cfg: &PciBarConfiguration,
        device: Arc<dyn DeviceIo>,
    ) -> Result<()> {
        let bar_idx = bar_cfg.bar_index();
        if bar_idx >= self.bar_enabled.len() {
            return Err(Error::BarInvalid(bar_idx));
        }

        if self.bar_enabled[bar_idx] == true {
            self.bar_enabled[bar_idx] = false;
            let params = BarProgrammingParams {
                bar_idx,
                bar_type: bar_cfg.bar_type(),
                old_base: bar_cfg.address(),
                new_base: 0,
                len: bar_cfg.size(),
            };
            self.handle_bar_change(device, params)?;
        }

        Ok(())
    }

    pub fn check_bar_changed(&mut self, device: Arc<dyn DeviceIo>) -> Result<()> {
        if let Some(params) = self.configuration.get_bar_programming_params() {
            return self.handle_bar_change(device, params);
        }

        Ok(())
    }

    fn handle_bar_change(
        &mut self,
        device: Arc<dyn DeviceIo>,
        params: BarProgrammingParams,
    ) -> Result<()> {
        let io_mgr = self.context.get_device_manager_context();
        let mut io_ctx = io_mgr.begin_tx();

        if self.bar_registered[params.bar_idx] {
            let resources = params.to_resources(true);
            if let Err(e) = io_mgr.unregister_device_io(&mut io_ctx, &resources) {
                io_mgr.cancel_tx(io_ctx);
                return Err(Error::IoManager(e));
            }
            self.bar_registered[params.bar_idx] = false;
        }
        if self.bar_enabled[params.bar_idx] {
            let resources = params.to_resources(false);
            if let Err(e) = io_mgr.register_device_io(&mut io_ctx, device, &resources) {
                io_mgr.cancel_tx(io_ctx);
                return Err(Error::IoManager(e));
            }
            self.bar_registered[params.bar_idx] = true;
        }

        Ok(())
    }
}
*/
