// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
use vm_device::interrupt::InterruptSourceGroup;

use super::*;

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct MsiCapState {
    cap_id_next: u16,
    msg_ctl: u16,
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u16,
    mask_bits: u32,
    pending_bits: u32,
}

#[derive(Clone)]
pub struct MsiCapStateConstructorArgs {
    pub interrupt_source_group: Option<Arc<Box<dyn InterruptSourceGroup>>>,
}

impl Persist<'_> for MsiCap {
    type State = MsiCapState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = MsiCapStateConstructorArgs;
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        MsiCapState {
            cap_id_next: self.cap_id_next,
            msg_ctl: self.msg_ctl,
            msg_addr_lo: self.msg_addr_lo,
            msg_addr_hi: self.msg_addr_hi,
            msg_data: self.msg_data,
            mask_bits: self.mask_bits,
            pending_bits: self._pending_bits,
        }
    }

    fn live_upgrade_restore(
        constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(MsiCap {
            cap_id_next: state.cap_id_next,
            msg_ctl: state.msg_ctl,
            msg_addr_lo: state.msg_addr_lo,
            msg_addr_hi: state.msg_addr_hi,
            msg_data: state.msg_data,
            mask_bits: state.mask_bits,
            _pending_bits: state.pending_bits,
            group: constructor_args.interrupt_source_group.clone(),
        })
    }
}

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct MsiStatePersistState {
    msg_ctl: u16,
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u16,
    mask_bits: u32,
}

impl Persist<'_> for MsiState {
    type State = MsiStatePersistState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = ();
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        MsiStatePersistState {
            msg_ctl: self.msg_ctl,
            msg_addr_lo: self.msg_addr_lo,
            msg_addr_hi: self.msg_addr_hi,
            msg_data: self.msg_data,
            mask_bits: self.mask_bits,
        }
    }

    fn live_upgrade_restore(
        _constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(MsiState {
            msg_ctl: state.msg_ctl,
            msg_addr_lo: state.msg_addr_lo,
            msg_addr_hi: state.msg_addr_hi,
            msg_data: state.msg_data,
            mask_bits: state.mask_bits,
        })
    }
}

#[cfg(test)]
mod tests {
    use versionize::VersionManager;

    use super::*;
    use crate::msi::{MSI_CTL_64_BITS, MSI_CTL_ENABLE};

    #[test]
    fn test_persist_msi_cap_liveupgrade_state() {
        let msi_cap = MsiCap::new(0xa5, MSI_CTL_ENABLE);

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        msi_cap
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_msi_cap = MsiCap::live_upgrade_restore(
            MsiCapStateConstructorArgs {
                interrupt_source_group: None,
            },
            &MsiCapState::deserialize(&mut mem.as_slice(), version_map, max_version).unwrap(),
        )
        .unwrap();

        // test state
        assert!(msi_cap == restored_msi_cap);
    }

    #[test]
    fn test_persist_msi_state_liveupgrade_state() {
        let msi_state = MsiState::new(MSI_CTL_64_BITS);

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        msi_state
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_msi_state = MsiState::live_upgrade_restore(
            (),
            &MsiStatePersistState::deserialize(&mut mem.as_slice(), version_map, max_version)
                .unwrap(),
        )
        .unwrap();

        // test state
        assert!(msi_state == restored_msi_state);
    }
}
