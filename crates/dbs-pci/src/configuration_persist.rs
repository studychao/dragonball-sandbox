// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex, Weak};

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_device::interrupt::InterruptSourceGroup;

use crate::bus::PciBus;
#[cfg(test)]
use crate::configuration::tests::TestCap;
use crate::configuration::{
    BarProgrammingParams, PciBarState, PciCapability, PciConfiguration, PciHeaderType, Vp2pCap,
    NUM_CONFIGURATION_REGISTERS,
};
use crate::msi::persist::{MsiCapState, MsiCapStateConstructorArgs};
use crate::msi::MsiCap;
use crate::msix::persist::MsixCapState;
use crate::msix::MsixCap;
use crate::PciCapabilityID;
#[cfg(test)]
use tests::TestCapState;

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct Vp2pCapState {
    pub(crate) id: u8,
    pub(crate) next: u8,
    pub(crate) length: u8,
    pub(crate) sig_1: u8,
    pub(crate) sig_2: u8,
    pub(crate) sig_3: u8,
    pub(crate) clique_id: u16,
}

impl Persist<'_> for Vp2pCap {
    type State = Vp2pCapState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = ();
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        Vp2pCapState {
            id: self.id,
            next: self.next,
            length: self.length,
            sig_1: self.sig_1,
            sig_2: self.sig_2,
            sig_3: self.sig_3,
            clique_id: self.clique_id,
        }
    }

    fn live_upgrade_restore(
        _constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(Vp2pCap {
            id: state.id,
            next: state.next,
            length: state.length,
            sig_1: state.sig_1,
            sig_2: state.sig_2,
            sig_3: state.sig_3,
            clique_id: state.clique_id,
        })
    }
}
#[derive(Versionize, PartialEq, Debug, Clone, Default)]
pub struct PciCapabilityState {
    msi_cap: Option<MsiCapState>,
    msix_cap: Option<MsixCapState>,
    #[version(start = 2)]
    vp2p_cap: Option<Vp2pCapState>,
    #[cfg(test)]
    test_cap: Option<TestCapState>,
}

impl Persist<'_> for Box<dyn PciCapability> {
    type State = PciCapabilityState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = MsiCapStateConstructorArgs;
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        let mut state = PciCapabilityState::default();
        match self.pci_capability_type() {
            PciCapabilityID::MessageSignalledInterrupts => {
                state.msi_cap = Some(
                    self.as_any()
                        .downcast_ref::<MsiCap>()
                        .unwrap()
                        .live_upgrade_save(),
                );
            }
            PciCapabilityID::MSIX => {
                state.msix_cap = Some(
                    self.as_any()
                        .downcast_ref::<MsixCap>()
                        .unwrap()
                        .live_upgrade_save(),
                );
            }
            // TODO: There is only one kind of Vendor Specific Capability,
            // namely Vp2pcap. If there are multiple Vendor Specific
            // Capabilities in the future, need to modify the code logic.
            PciCapabilityID::VendorSpecific => {
                state.vp2p_cap = Some(
                    self.as_any()
                        .downcast_ref::<Vp2pCap>()
                        .unwrap()
                        .live_upgrade_save(),
                );
            }
            #[cfg(test)]
            PciCapabilityID::Test => {
                state.test_cap = Some(
                    self.as_any()
                        .downcast_ref::<TestCap>()
                        .unwrap()
                        .live_upgrade_save(),
                );
            }
            _ => {}
        }

        state
    }

    fn live_upgrade_restore(
        constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        if let Some(msi_cap_state) = &state.msi_cap {
            return Ok(Box::new(
                // safe to unwrap
                MsiCap::live_upgrade_restore(constructor_args, msi_cap_state).unwrap(),
            ));
        }
        if let Some(msix_cap_state) = &state.msix_cap {
            return Ok(Box::new(
                // safe to unwrap
                MsixCap::live_upgrade_restore((), msix_cap_state).unwrap(),
            ));
        }
        if let Some(vp2p_cap_state) = &state.vp2p_cap {
            return Ok(Box::new(
                // safe to unwrap
                Vp2pCap::live_upgrade_restore((), vp2p_cap_state).unwrap(),
            ));
        }
        #[cfg(test)]
        if let Some(test_cap_state) = &state.test_cap {
            return Ok(Box::new(
                TestCap::live_upgrade_restore((), test_cap_state).unwrap(),
            ));
        }

        panic!("invalid pci capability type");
    }
}

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct PciConfigurationCapabilityState {
    cap_offset: usize,
    total_len: usize,
    capability: PciCapabilityState,
}

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct PciConfigurationState {
    header_type: PciHeaderType,
    registers: Vec<u32>,
    writable_bits: Vec<u32>,
    bars: Vec<PciBarState>,
    bar_programming_params: Option<BarProgrammingParams>,
    capabilities: Vec<PciConfigurationCapabilityState>,
}

pub struct PciConfigurationStateConstructorArgs {
    pub interrupt_source_group: Option<Arc<Box<dyn InterruptSourceGroup>>>,
    pub pci_bus: Weak<PciBus>,
}

impl Persist<'_> for PciConfiguration {
    type State = PciConfigurationState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = PciConfigurationStateConstructorArgs;
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        let mut capabilities = Vec::with_capacity(self.capabilities.len());
        for (cap_offset, total_len, capability) in &self.capabilities {
            capabilities.push(PciConfigurationCapabilityState {
                cap_offset: *cap_offset,
                total_len: *total_len,
                capability: capability.lock().unwrap().live_upgrade_save(),
            });
        }

        PciConfigurationState {
            header_type: self.header_type.clone(),
            registers: self.registers.to_vec(),
            writable_bits: self.writable_bits.to_vec(),
            bars: self.bars.to_vec(),
            bar_programming_params: self
                .bar_programming_params
                .as_ref()
                .map(|param| param.clone()),
            capabilities,
        }
    }

    fn live_upgrade_restore(
        constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut capabilities = Vec::with_capacity(state.capabilities.len());
        for cap in &state.capabilities {
            capabilities.push((
                cap.cap_offset,
                cap.total_len,
                // safe to unwrap
                Arc::new(Mutex::new(
                    Box::<dyn PciCapability>::live_upgrade_restore(
                        MsiCapStateConstructorArgs {
                            interrupt_source_group: constructor_args.interrupt_source_group.clone(),
                        },
                        &cap.capability,
                    )
                    .unwrap(),
                )),
            ));
        }

        let mut pci_configuration = PciConfiguration {
            header_type: state.header_type.clone(),
            registers: [0; NUM_CONFIGURATION_REGISTERS],
            writable_bits: [0; NUM_CONFIGURATION_REGISTERS],
            bars: Default::default(),
            bar_programming_params: state
                .bar_programming_params
                .as_ref()
                .map(|param| param.clone()),
            capabilities,
            bus: constructor_args.pci_bus,
        };

        pci_configuration.registers[..].copy_from_slice(&state.registers.as_slice()[..]);
        pci_configuration.writable_bits[..].copy_from_slice(&state.writable_bits.as_slice()[..]);
        pci_configuration.bars[..].copy_from_slice(&state.bars.as_slice()[..]);

        Ok(pci_configuration)
    }
}

#[cfg(test)]
mod tests {
    use versionize::VersionManager;

    use super::*;
    use crate::configuration::tests::{create_new_config, TestCap};

    #[derive(Versionize, PartialEq, Debug, Clone)]
    pub struct TestCapState {
        id: u8,
        next: u8,
        len: u8,
        foo: u8,
        bar: u32,
        zoo: u8,
    }

    impl Persist<'_> for TestCap {
        type State = TestCapState;
        type ConstructorArgs = ();
        type LiveUpgradeConstructorArgs = ();
        type Error = ();

        fn live_upgrade_save(&self) -> Self::State {
            TestCapState {
                id: self.id,
                next: self.next,
                len: self.len,
                foo: self.foo,
                bar: self.bar,
                zoo: self.zoo,
            }
        }

        fn live_upgrade_restore(
            _constructor_args: Self::LiveUpgradeConstructorArgs,
            state: &Self::State,
        ) -> Result<Self, Self::Error> {
            Ok(TestCap {
                id: state.id,
                next: state.next,
                len: state.len,
                foo: state.foo,
                bar: state.bar,
                zoo: state.zoo,
            })
        }
    }

    #[test]
    fn test_persist_pci_capability_liveupgrade_state() {
        let test_cap = TestCap {
            id: 1,
            next: 2,
            len: 3,
            foo: 4,
            bar: 5,
            zoo: 6,
        };

        let pci_capcbility = Box::new(test_cap) as Box<dyn PciCapability>;

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_capcbility
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_capability = Box::<dyn PciCapability>::live_upgrade_restore(
            MsiCapStateConstructorArgs {
                interrupt_source_group: None,
            },
            &PciCapabilityState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        let restored_test_cap = restored_pci_capability
            .as_any()
            .downcast_ref::<TestCap>()
            .unwrap();

        // test state
        assert!(test_cap == *restored_test_cap);
    }

    impl PartialEq for dyn PciCapability {
        fn eq(&self, other: &dyn PciCapability) -> bool {
            self.len() == other.len() && self.pci_capability_type() == other.pci_capability_type()
        }
    }

    impl PartialEq for PciConfiguration {
        fn eq(&self, other: &PciConfiguration) -> bool {
            self.header_type == other.header_type
                && self.registers == other.registers
                && self.writable_bits == other.writable_bits
                && self.bars == other.bars
                && self.bar_programming_params == other.bar_programming_params
                && self
                    .capabilities
                    .iter()
                    .zip(other.capabilities.iter())
                    .all(|(s, o)| {
                        let s2 = s.2.lock().unwrap();
                        let o2 = o.2.lock().unwrap();
                        s.0 == o.0 && s.1 == o.1 && &*s2 == &*o2
                    })
        }
    }

    #[test]
    fn test_persist_pci_configuration_liveupgrade_state() {
        let bus = Arc::new(PciBus::new(0));
        let pci_configuration = create_new_config(&bus);

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        pci_configuration
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_pci_configuration = PciConfiguration::live_upgrade_restore(
            PciConfigurationStateConstructorArgs {
                interrupt_source_group: None,
                pci_bus: Arc::downgrade(&bus),
            },
            &PciConfigurationState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        // test state
        assert!(pci_configuration == restored_pci_configuration);
    }
}
