// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Virtual machine console device manager.
//!
//! A virtual console are composed up of two parts: frontend in virtual machine and backend in
//! host OS. A frontend may be serial port, virtio-console etc, a backend may be stdio or Unix
//! domain socket. The manager connects the frontend with the backend.
use std::io::{self, Read};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::{BufMut, BytesMut};
use dbs_legacy_devices::{ConsoleHandler, SerialDevice};
use dbs_utils::epoll_manager::{
    EpollManager, EventOps, EventSet, Events, MutEventSubscriber, SubscriberId,
};
use vmm_sys_util::terminal::Terminal;

const EPOLL_EVENT_SERIAL: u32 = 0;
const EPOLL_EVENT_SERIAL_DATA: u32 = 1;
const EPOLL_EVENT_STDIN: u32 = 2;
// Maximal backend throughput for every data transaction.
const MAX_BACKEND_THROUGHPUT: usize = 64;


/// Specialized version of `std::result::Result` for device manager operations.
pub type Result<T> = ::std::result::Result<T, DeviceMgrError>;

/// Errors related to device manager operations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceMgrError {
    /// Invalid operation.
    #[error("invalid device manager operation")]
    InvalidOperation,

    /// Failed to get device resource.
    #[error("failed to get device assigned resources")]
    GetDeviceResource,

    /// Appending to kernel command line failed.
    #[error("failed to add kernel command line parameter for device: {0}")]
    Cmdline(#[source] linux_loader::cmdline::Error),

    /// Failed to manage console devices.
    #[error(transparent)]
    ConsoleManager(ConsoleManagerError),

    /// Failed to create the device.
    #[error("failed to create virtual device: {0}")]
    CreateDevice(#[source] io::Error),


    #[cfg(feature = "dbs-virtio-devices")]
    /// Error from Virtio subsystem.
    #[error(transparent)]
    Virtio(virtio::Error),

    #[cfg(all(feature = "hotplug", feature = "dbs-upcall"))]
    /// Failed to hotplug the device.
    #[error("failed to hotplug virtual device")]
    HotplugDevice(#[source] UpcallClientError),

}

/// Errors related to Console manager operations.
#[derive(Debug, thiserror::Error)]
pub enum ConsoleManagerError {
    /// Cannot create unix domain socket for serial port
    #[error("cannot create socket for serial console")]
    CreateSerialSock(#[source] std::io::Error),

    /// An operation on the epoll instance failed due to resource exhaustion or bad configuration.
    #[error("failure while managing epoll event for console fd")]
    EpollMgr(#[source] dbs_utils::epoll_manager::Error),

    /// Cannot set mode for terminal.
    #[error("failure while setting attribute for terminal")]
    StdinHandle(#[source] vmm_sys_util::errno::Error),
}

enum Backend {
    StdinHandle(std::io::Stdin),
    SockPath(String),
}

/// Console manager to manage frontend and backend console devices.
pub struct ConsoleManager {
    epoll_mgr: EpollManager,
    subscriber_id: Option<SubscriberId>,
    backend: Option<Backend>,
}

impl ConsoleManager {
    /// Create a console manager instance.
    pub fn new(epoll_mgr: EpollManager) -> Self {
        ConsoleManager {
            epoll_mgr,
            subscriber_id: Default::default(),
            backend: None,
        }
    }

    /// Create a console backend device by using stdio streams.
    pub fn create_stdio_console(&mut self, device: Arc<Mutex<SerialDevice>>) -> Result<()> {
        let stdin_handle = std::io::stdin();
        stdin_handle
            .lock()
            .set_raw_mode()
            .map_err(|e| DeviceMgrError::ConsoleManager(ConsoleManagerError::StdinHandle(e)))?;

        let handler = ConsoleEpollHandler::new(device, Some(stdin_handle));
        self.subscriber_id = Some(self.epoll_mgr.add_subscriber(Box::new(handler)));
        self.backend = Some(Backend::StdinHandle(std::io::stdin()));

        Ok(())
    }


    /// Reset the host side terminal to canonical mode.
    pub fn reset_console(&self) -> Result<()> {
        if let Some(Backend::StdinHandle(stdin_handle)) = self.backend.as_ref() {
            stdin_handle
                .lock()
                .set_canon_mode()
                .map_err(|e| DeviceMgrError::ConsoleManager(ConsoleManagerError::StdinHandle(e)))?;
        }

        Ok(())
    }

}

struct ConsoleEpollHandler {
    device: Arc<Mutex<SerialDevice>>,
    stdin_handle: Option<std::io::Stdin>,
}

impl ConsoleEpollHandler {
    fn new(
        device: Arc<Mutex<SerialDevice>>,
        stdin_handle: Option<std::io::Stdin>,
    ) -> Self {
        ConsoleEpollHandler {
            device,
            stdin_handle,
        }
    }
    fn stdio_read_in(&mut self, ops: &mut EventOps) -> std::io::Result<()> {
        println!("goes here!!!");
        let mut should_drop = true;

        if let Some(handle) = self.stdin_handle.as_ref() {
            let mut out = [0u8; MAX_BACKEND_THROUGHPUT];
            // Safe to unwrap() because self.stdin_handle is Some().
            let stdin_lock = handle.lock();
            match stdin_lock.read_raw(&mut out[..]) {
                Ok(0) => {
                    // Zero-length read indicates EOF. Remove from pollables.
                    self.device
                        .lock()
                        .expect("console: poisoned console lock")
                        .set_output_stream(None);
                }
                Ok(count) => {
                    println!("Tell me count {:?}", count);
                    self.device
                        .lock()
                        .expect("console: poisoned console lock")
                        .raw_input(&out[..count])?;
                    should_drop = false;
                }
                Err(e) => {
                    println!("[CHAOTEST] Tell me {:?}", e);
                    self.device
                        .lock()
                        .expect("console: poisoned console lock")
                        .set_output_stream(None);
                }
            }
        }

        if should_drop {
            let events = Events::with_data_raw(libc::STDIN_FILENO, EPOLL_EVENT_STDIN, EventSet::IN);
            if let Err(e) = ops.remove(events) {
                println!("[CHAOTEST] error");
            }
        }

        Ok(())
    }
}

impl MutEventSubscriber for ConsoleEpollHandler {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        println!("ConsoleEpollHandler::process()");
        let slot = events.data();
        match slot {
            EPOLL_EVENT_STDIN => {
                if let Err(e) = self.stdio_read_in(ops) {
                   println!( "failed to read data from stdin, {:?}", e);
                }
            }
            _ => println!("unknown epoll slot number {}", slot),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        println!("ConsoleEpollHandler::init()");

        if self.stdin_handle.is_some() {
            println!("ConsoleEpollHandler: stdin handler");
            let events = Events::with_data_raw(libc::STDIN_FILENO, EPOLL_EVENT_STDIN, EventSet::IN);
            if let Err(e) = ops.add(events) {
                println!(
                    "failed to register epoll event for stdin, {:?}",e
                );
            }
        }
    }
}

/// Writer to process guest kernel dmesg.
pub struct DmesgWriter {
    buf: BytesMut,
}

impl DmesgWriter {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(1024),
        }
    }
}

impl io::Write for DmesgWriter {
    /// 0000000   [                   0   .   0   3   4   9   1   6   ]       R
    ///          5b  20  20  20  20  30  2e  30  33  34  39  31  36  5d  20  52
    /// 0000020   u   n       /   s   b   i   n   /   i   n   i   t       a   s
    ///          75  6e  20  2f  73  62  69  6e  2f  69  6e  69  74  20  61  73
    /// 0000040       i   n   i   t       p   r   o   c   e   s   s  \r  \n   [
    ///
    /// dmesg message end a line with /r/n . When redirect message to logger, we should
    /// remove the /r/n .
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let arr: Vec<&[u8]> = buf.split(|c| *c == b'\n').collect();
        let count = arr.len();

        for (i, sub) in arr.iter().enumerate() {
            if sub.is_empty() {
                if !self.buf.is_empty() {
                    println!(
                        "{}",
                        String::from_utf8_lossy(self.buf.as_ref()).trim_end()
                    );
                    self.buf.clear();
                }
            } else if sub.len() < buf.len() && i < count - 1 {
                println!(
                    "{}{}",
                    String::from_utf8_lossy(self.buf.as_ref()).trim_end(),
                    String::from_utf8_lossy(sub).trim_end(),
                );
                self.buf.clear();
            } else {
                self.buf.put_slice(sub);
            }
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
