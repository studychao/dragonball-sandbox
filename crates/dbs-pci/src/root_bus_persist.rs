// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Mutex;

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use super::*;
use crate::configuration::persist::{PciConfigurationState, PciConfigurationStateConstructorArgs};

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct PciHostBridgeState {
    id: u8,
    config: PciConfigurationState,
}

impl Persist<'_> for PciHostBridge {
    type State = PciHostBridgeState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = PciConfigurationStateConstructorArgs;
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        PciHostBridgeState {
            id: self.id,
            // safe to unwrap
            config: self.config.lock().unwrap().live_upgrade_save(),
        }
    }

    fn live_upgrade_restore(
        constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> std::result::Result<Self, Self::Error> {
        Ok(PciHostBridge {
            id: state.id,
            config: Mutex::new(
                // safe to unwrap
                PciConfiguration::live_upgrade_restore(constructor_args, &state.config).unwrap(),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use versionize::VersionManager;

    use super::*;
    use crate::root_bus::create_pci_root_bus;

    impl PartialEq for PciHostBridge {
        fn eq(&self, other: &PciHostBridge) -> bool {
            self.id == other.id && *self.config.lock().unwrap() == *other.config.lock().unwrap()
        }
    }

    #[test]
    fn test_persist_pci_host_bridge_liveupgrade_state() {
        let root_bus = create_pci_root_bus(0).unwrap();
        let pci_host_bridge = PciHostBridge::new(9, Arc::downgrade(&root_bus));

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_host_bridge
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_host_bridge = PciHostBridge::live_upgrade_restore(
            PciConfigurationStateConstructorArgs {
                interrupt_source_group: None,
                pci_bus: Arc::downgrade(&root_bus),
            },
            &PciHostBridgeState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        // test state
        assert!(pci_host_bridge == restored_pci_host_bridge);
    }
}
