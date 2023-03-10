// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;

use super::*;

#[derive(Versionize, PartialEq, Debug, Clone)]
pub struct MsixCapState {
    cap_id: u8,
    cap_next: u8,
    msg_ctl: u16,
    table: u32,
    pba: u32,
}

impl Persist<'_> for MsixCap {
    type State = MsixCapState;
    type ConstructorArgs = ();
    type LiveUpgradeConstructorArgs = ();
    type Error = ();

    fn live_upgrade_save(&self) -> Self::State {
        MsixCapState {
            cap_id: self.cap_id,
            cap_next: self.cap_next,
            msg_ctl: self.msg_ctl,
            table: self.table,
            pba: self.pba,
        }
    }

    fn live_upgrade_restore(
        _constructor_args: Self::LiveUpgradeConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        Ok(MsixCap {
            cap_id: state.cap_id,
            cap_next: state.cap_next,
            msg_ctl: state.msg_ctl,
            table: state.table,
            pba: state.pba,
        })
    }
}

#[cfg(test)]
mod tests {
    use versionize::VersionManager;

    use super::*;

    #[test]
    fn test_persist_msix_cap_liveupgrade_state() {
        let msix_cap = MsixCap::new(0x1, 0x100, 0x1000, 0x1, 0x10_0000);

        let mut mem = vec![0; 4096];
        let mut version_manager = VersionManager::new();
        let max_version = version_manager.max_version() as u16;
        let version_map = version_manager.make_version_map();

        // save state
        msix_cap
            .live_upgrade_save()
            .serialize(&mut mem.as_mut_slice(), version_map, max_version)
            .unwrap();

        // restore state
        let restored_msix_cap = MsixCap::live_upgrade_restore(
            (),
            &MsixCapState::deserialize(&mut mem.as_slice(), version_map, max_version).unwrap(),
        )
        .unwrap();

        // test state
        assert!(msix_cap == restored_msix_cap);
    }
}
