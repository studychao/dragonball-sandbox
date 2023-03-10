// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(missing_docs)]

use std::any::TypeId;

use super::configuration::persist::PciCapabilityState;

pub fn get_versions_vm_pci(sem_ver: &str) -> Vec<(TypeId, u16)> {
    let mut versions = Vec::new();
    match sem_ver {
        "2.10.1" => {
            versions.push((TypeId::of::<PciCapabilityState>(), 2));
        }
        _ => {}
    };
    versions
}
