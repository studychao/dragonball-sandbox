// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_device::interrupt::InterruptSourceGroup;
use vm_device::persist::DeviceResourcesState;
use vm_device::resources::DeviceResources;

use crate::bus::persist::PciBusState;
use crate::bus::PciBus;
use crate::configuration::persist::PciConfigurationStateConstructorArgs;
use crate::root_bus::persist::PciHostBridgeState;
use crate::root_bus::{PciHostBridge, PCI_ROOT_DEVICE_ID};
use crate::Error;

use super::*;

#[derive(Versionize, Clone, PartialEq, Debug)]
pub struct PciRootContentState {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    io_addr: u32,
    buses: HashMap<u32, (PciBusState, Option<PciHostBridgeState>)>,
}

pub struct PciRootContentConstructorArgs {
    pub interrupt_source_group: Option<Arc<Box<dyn InterruptSourceGroup>>>,
}

impl Persist<'_> for PciRootContent {
    type State = PciRootContentState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = PciRootContentConstructorArgs;
    type Error = Error;

    fn live_upgrade_save(&self) -> Self::State {
        let mut state = PciRootContentState {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            io_addr: self.io_addr,
            buses: HashMap::with_capacity(self.buses.len()),
        };

        for (id, bus) in &self.buses {
            let mut host_bridge_state = None;
            // TODO
            //let devices = bus.devices.read().unwrap();
            //if let Some(device) = devices.get_by_id(PCI_ROOT_DEVICE_ID as u64) {
            //    if let Some(host_bridge) = device.as_any().downcast_ref::<PciHostBridge>() {
            //        host_bridge_state = Some(host_bridge.live_upgrade_save());
            //    }
            //}
            if let Some(device) = bus.get_device(PCI_ROOT_DEVICE_ID as u32) {
                if let Some(host_bridge) = device.as_any().downcast_ref::<PciHostBridge>() {
                    host_bridge_state = Some(host_bridge.live_upgrade_save());
                }
            }
            state
                .buses
                .insert(*id, (bus.live_upgrade_save(), host_bridge_state));
        }

        state
    }

    fn live_upgrade_restore(
        constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        let mut buses = HashMap::with_capacity(state.buses.len());

        for (id, (bus_state, host_bridge_state)) in &state.buses {
            let bus = Arc::new(PciBus::live_upgrade_restore((), bus_state)?);

            if let Some(hb_state) = host_bridge_state {
                let bus_weak = Arc::downgrade(&bus);
                bus.allocate_device_id(Some(PCI_ROOT_DEVICE_ID));
                bus.register_device(Arc::new(
                    // safe to unwrap
                    PciHostBridge::live_upgrade_restore(
                        PciConfigurationStateConstructorArgs {
                            interrupt_source_group: constructor_args.interrupt_source_group.clone(),
                            pci_bus: bus_weak,
                        },
                        hb_state,
                    )
                    .unwrap(),
                ))?;
            }
            buses.insert(*id, bus);
        }

        Ok(PciRootContent {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            io_addr: state.io_addr,
            buses,
        })
    }
}

#[derive(Versionize, PartialEq, Debug)]
pub struct PciRootDeviceState {
    max_bus_id: u8,
    ioport_base: u16,
    mmio_base: u64,
    mmio_size: u64,
    resources: DeviceResourcesState,
    state: PciRootContentState,
}

impl Persist<'_> for PciRootDevice {
    type State = PciRootDeviceState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = PciRootContentConstructorArgs;
    type Error = Error;

    fn live_upgrade_save(&self) -> Self::State {
        PciRootDeviceState {
            max_bus_id: self.max_bus_id,
            ioport_base: self.ioport_base,
            mmio_base: self.mmio_base,
            mmio_size: self.mmio_size,
            resources: self.resources.save(),
            state: self.state.read().unwrap().live_upgrade_save(),
        }
    }

    fn live_upgrade_restore(
        constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(PciRootDevice {
            max_bus_id: state.max_bus_id,
            ioport_base: state.ioport_base,
            mmio_base: state.mmio_base,
            mmio_size: state.mmio_size,
            // safe to unwrap
            resources: DeviceResources::restore((), &state.resources).unwrap(),
            state: RwLock::new(PciRootContent::live_upgrade_restore(
                constructor_args,
                &state.state,
            )?),
        })
    }
}

#[cfg(test)]
mod tests {
    use versionize::VersionManager;
    use vm_device::resources::Resource;

    use super::*;

    #[test]
    fn test_persist_pci_root_content_liveupgrade_state() {
        let pci_bus = Arc::new(PciBus::new(0));
        let mut pci_root_content = PciRootContent::new();
        pci_root_content.buses.insert(0, pci_bus);

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_root_content
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_root_content = PciRootContent::live_upgrade_restore(
            PciRootContentConstructorArgs {
                interrupt_source_group: None,
            },
            &PciRootContentState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        // test state
        assert!(pci_root_content == restored_pci_root_content);
    }

    impl PartialEq for PciRootDevice {
        fn eq(&self, other: &PciRootDevice) -> bool {
            self.max_bus_id == other.max_bus_id
                && self.ioport_base == other.ioport_base
                && self.mmio_base == other.mmio_base
                && self.mmio_size == other.mmio_size
                && self.resources == other.resources
                && *self.state.read().unwrap() == *other.state.read().unwrap()
        }
    }

    #[test]
    fn test_persist_pci_root_device_state() {
        let mut resources = DeviceResources::new();
        resources.append(Resource::PioAddressRange {
            base: 0xCF8,
            size: 8,
        });
        let pci_root_device = PciRootDevice::create(255, resources).unwrap();

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_root_device
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_root_device = PciRootDevice::live_upgrade_restore(
            PciRootContentConstructorArgs {
                interrupt_source_group: None,
            },
            &PciRootDeviceState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        // test state
        assert!(pci_root_device == restored_pci_root_device);
    }
}
