// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::RwLock;

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_allocator::persist::IntervalTreeStateUnit;
use vm_allocator::IntervalTree;
use vm_device::persist::DeviceResourcesState;
use vm_device::resources::DeviceResources;

use crate::bus::{PciBus, PciBusContent};
use crate::Error;

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct PciBusContentState {
    resources: Option<DeviceResourcesState>,
    ioport_resources: IntervalTreeStateUnit,
    iomem_resources: IntervalTreeStateUnit,
}

impl Persist<'_> for PciBusContent {
    type State = PciBusContentState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = ();
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        PciBusContentState {
            resources: self.resources.as_ref().map(|res| res.save()),
            ioport_resources: self.ioport_resources.save(),
            iomem_resources: self.iomem_resources.save(),
        }
    }

    fn live_upgrade_restore(
        _constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // safe to unwrap
        Ok(PciBusContent {
            resources: state
                .resources
                .as_ref()
                .map(|res| DeviceResources::restore((), &res).unwrap()),
            ioport_resources: IntervalTree::restore((), &state.ioport_resources).unwrap(),
            iomem_resources: IntervalTree::restore((), &state.iomem_resources).unwrap(),
        })
    }
}

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct PciBusState {
    pub bus_id: u8,
    pub state: PciBusContentState,
}

impl Persist<'_> for PciBus {
    type State = PciBusState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = ();
    type Error = Error;

    fn live_upgrade_save(&self) -> Self::State {
        PciBusState {
            bus_id: self.bus_id,
            state: self.state.read().unwrap().live_upgrade_save(),
        }
    }

    fn live_upgrade_restore(
        _constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut devices = IntervalTree::new();
        Self::assign_default_device_id(&mut devices);

        let pci_bus = PciBus {
            bus_id: state.bus_id,
            // safe to unwrap
            state: RwLock::new(PciBusContent::live_upgrade_restore((), &state.state).unwrap()),
            devices: RwLock::new(devices),
        };

        Ok(pci_bus)
    }
}

#[cfg(test)]
mod tests {
    use versionize::VersionManager;
    use vm_device::resources::Resource;

    use super::*;

    #[test]
    fn test_persist_pci_bus_content_liveupgrade_state() {
        let mut resources = DeviceResources::new();
        resources.append(Resource::MmioAddressRange {
            base: 0,
            size: 0x10,
        });
        let mut pci_bus_contenxt = PciBusContent::new();
        pci_bus_contenxt.assign_resources(resources, 0).unwrap();

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_bus_contenxt
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_bus_context = PciBusContent::live_upgrade_restore(
            (),
            &PciBusContentState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        // test state
        assert!(pci_bus_contenxt == restored_pci_bus_context);
    }

    #[test]
    fn test_persist_pci_bus_state_liveupgrade_state() {
        let pci_bus = PciBus::new(1);

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_bus
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_bus = PciBus::live_upgrade_restore(
            (),
            &PciBusState::deserialize(&mut mem.as_slice(), version_map, max_version).unwrap(),
        )
        .unwrap();

        // test state
        assert!(pci_bus == restored_pci_bus);
    }
}
