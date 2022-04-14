// Copyright 2021 Alibaba Corporation. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! # Upcall Device Manager Service.
//!
//! Provides basic operations for dragonball's upcall device manager, include:
//! - CPU / Mmio-Virtio Device's hot-plug
//! - CPU Device's hot-unplug

use std::fmt;
use std::mem;

use virtio::vsock::backend::VsockStream;

use crate::{
    Result, UpcallClientError, UpcallClientRequest, UpcallClientResponse, UpcallClientService,
};

const DEV_MGR_MSG_SIZE: usize = 0x400;
const DEV_MGR_MAGIC_VERSION: u32 = 0x444D0100;
const DEV_MGR_BYTE: &[u8; 1usize] = b"d";

/// Device manager's op code.
#[allow(dead_code)]
#[repr(u32)]
enum DevMgrMsgType {
    AddCpu = 0xdb000000,
    DelCpu = 0xdb100000,
    AddMem = 0xdb200000,
    DelMem = 0xdb300000,
    AddMmio = 0xdb400000,
    DelMmio = 0xdb500000,
    AddPci = 0xdb600000,
    DelPci = 0xdb700000,

    CmdOk = 0xdbe00000,
    CmdErr = 0xdbf00000,
}

/// Device manager's header for messages.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct DevMgrMsgHeader {
    pub magic_version: u32,
    pub msg_size: u32,
    pub msg_type: u32,
    pub msg_flags: u32,
}

/// Command struct to add a MMIO Virtio Device.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct AddMmioDevRequest {
    /// base address of the virtio MMIO configuration window.
    pub mmio_base: u64,
    /// size of the virtio MMIO configuration window.
    pub mmio_size: u64,
    /// Interrupt number assigned to the MMIO virito device.
    pub mmio_irq: u32,
}

/// Command struct to add/del a vCPU.
#[repr(C)]
#[derive(Clone)]
pub struct CpuDevRequest {
    /// hotplug or hot unplug cpu count
    pub count: u8,
    /// apic version
    pub apic_ver: u8,
    /// apic id array
    pub apic_ids: [u8; 256],
}

impl PartialEq for CpuDevRequest {
    fn eq(&self, other: &CpuDevRequest) -> bool {
        self.count == other.count
            && self.apic_ver == other.apic_ver
            && self
                .apic_ids
                .iter()
                .zip(other.apic_ids.iter())
                .all(|(s, o)| s == o)
    }
}

impl fmt::Debug for CpuDevRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut apic_ids = String::from("[ ");
        for apic_id in self.apic_ids.iter() {
            if apic_id == &0 {
                break;
            }
            apic_ids.push_str(&format!("{}", apic_id));
            apic_ids.push(' ');
        }
        apic_ids.push_str(" ]");
        f.debug_struct("CpuDevRequest")
            .field("count", &self.count)
            .field("apic_ver", &self.apic_ver)
            .field("apic_ids", &apic_ids)
            .finish()
    }
}

/// Device manager's request representation in client side.
#[derive(Clone, PartialEq, Debug)]
pub enum DevMgrRequest {
    /// Add a MMIO virtio device
    AddMmioDev(AddMmioDevRequest),
    /// Add a VCPU
    AddVcpu(CpuDevRequest),
    /// Del a VCPU
    DelVcpu(CpuDevRequest),
}

impl DevMgrRequest {
    /// Convert client side's representation into server side's representation.
    pub fn build(&self) -> Box<[u8; DEV_MGR_MSG_SIZE]> {
        let buffer = Box::new([0; DEV_MGR_MSG_SIZE]);
        let size_hdr = mem::size_of::<DevMgrMsgHeader>();
        let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };

        msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;
        msg_hdr.msg_flags = 0;

        match self {
            DevMgrRequest::AddMmioDev(s) => {
                msg_hdr.msg_type = DevMgrMsgType::AddMmio as u32;
                msg_hdr.msg_size = mem::size_of::<AddMmioDevRequest>() as u32;
                let mmio_dev =
                    unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut AddMmioDevRequest) };
                *mmio_dev = *s;
            }
            DevMgrRequest::AddVcpu(s) => {
                msg_hdr.msg_type = DevMgrMsgType::AddCpu as u32;
                msg_hdr.msg_size = mem::size_of::<CpuDevRequest>() as u32;
                let vcpu_dev = unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevRequest) };
                *vcpu_dev = s.clone();
            }
            DevMgrRequest::DelVcpu(s) => {
                msg_hdr.msg_type = DevMgrMsgType::DelCpu as u32;
                msg_hdr.msg_size = mem::size_of::<CpuDevRequest>() as u32;
                let vcpu_dev = unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevRequest) };
                *vcpu_dev = s.clone();
            }
        }

        buffer
    }
}

/// Device manager's response from cpu device.
#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct CpuDevResponse {
    /// apic id index of last act cpu
    pub apic_id_index: u32,
}

/// Device manager's response inner message.
#[derive(Debug, PartialEq)]
pub struct DevMgrResponseInfo<I> {
    /// Is the action success?
    pub result: bool,
    /// Additional info returned by device.
    pub info: I,
}

/// Device manager's response representation in client side.
#[derive(Debug, PartialEq)]
pub enum DevMgrResponse {
    /// Add mmio device's response (no response body)
    AddMmioDev(DevMgrResponseInfo<()>),
    /// Add / Del cpu device's response
    CpuDev(DevMgrResponseInfo<CpuDevResponse>),
    /// Other response
    Other(DevMgrResponseInfo<()>),
}

impl DevMgrResponse {
    /// Convert server side's representation into client side's representation.
    fn make(buffer: &[u8]) -> Result<Self> {
        let size_hdr = mem::size_of::<DevMgrMsgHeader>();
        let msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
        let result = msg_hdr.msg_type == DevMgrMsgType::CmdOk as u32;

        match msg_hdr.msg_flags {
            flg if flg == DevMgrMsgType::AddCpu as u32 || flg == DevMgrMsgType::DelCpu as u32 => {
                let response =
                    unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevResponse) };
                Ok(DevMgrResponse::CpuDev(DevMgrResponseInfo {
                    result,
                    info: response.clone(),
                }))
            }
            flg if flg == DevMgrMsgType::AddMmio as u32 => {
                Ok(DevMgrResponse::AddMmioDev(DevMgrResponseInfo {
                    result,
                    info: (),
                }))
            }
            _ => Ok(DevMgrResponse::Other(DevMgrResponseInfo {
                result,
                info: (),
            })),
        }
    }
}

/// Device manager service, realized upcall client service.
#[derive(Default)]
pub struct DevMgrService {}

impl UpcallClientService for DevMgrService {
    fn connection_start(&self, stream: &mut Box<dyn VsockStream>) -> Result<()> {
        stream
            .write_all(DEV_MGR_BYTE)
            .map_err(UpcallClientError::ServiceConnect)
    }

    fn connection_check(&self, stream: &mut Box<dyn VsockStream>) -> Result<()> {
        let mut buf = [0; DEV_MGR_MSG_SIZE];
        stream
            .read_exact(&mut buf)
            .map_err(UpcallClientError::ServiceConnect)?;
        let hdr = unsafe { &*(buf.as_ptr() as *const DevMgrMsgHeader) };
        if hdr.magic_version == DEV_MGR_MAGIC_VERSION
            && hdr.msg_size == 0
            && hdr.msg_flags == 0
            && hdr.msg_type == DevMgrMsgType::CmdOk as u32
        {
            Ok(())
        } else {
            Err(UpcallClientError::InvalidMessage(format!(
                "upcall device manager expect msg_type {:?}, but received {}",
                DevMgrMsgType::CmdOk as u32,
                hdr.msg_type
            )))
        }
    }

    fn send_request(
        &self,
        stream: &mut Box<dyn VsockStream>,
        request: UpcallClientRequest,
    ) -> Result<()> {
        let msg = match request {
            UpcallClientRequest::DevMgr(req) => req.build(),
            // we don't have other message type yet
            #[cfg(test)]
            UpcallClientRequest::FakeRequest => unimplemented!(),
            // _ => return Err(UpcallClientError::InvalidMessage(format!("upcall device manager: invalid request"))),
        };
        stream
            .write_all(&*msg)
            .map_err(UpcallClientError::SendRequest)
    }

    fn handle_response(&self, stream: &mut Box<dyn VsockStream>) -> Result<UpcallClientResponse> {
        let mut buf = [0; DEV_MGR_MSG_SIZE];
        stream
            .read_exact(&mut buf)
            .map_err(UpcallClientError::GetResponse)?;
        let response = DevMgrResponse::make(&buf)?;

        Ok(UpcallClientResponse::DevMgr(response))
    }
}

#[cfg(test)]
mod tests {
    use virtio::vsock::backend::{VsockBackend, VsockInnerBackend};

    use super::*;

    #[test]
    fn test_build_dev_mgr_request() {
        let size_hdr = mem::size_of::<DevMgrMsgHeader>();
        // add mmio dev request
        {
            let add_mmio_dev_request = AddMmioDevRequest {
                mmio_base: 0,
                mmio_size: 1,
                mmio_irq: 2,
            };
            let dev_mgr_request = DevMgrRequest::AddMmioDev(add_mmio_dev_request.clone());
            let buffer = dev_mgr_request.build();

            // valid total size
            assert_eq!(buffer.len(), DEV_MGR_MSG_SIZE);

            // valid header
            let msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
            assert_eq!(msg_hdr.magic_version, DEV_MGR_MAGIC_VERSION);
            assert_eq!(msg_hdr.msg_flags, 0);
            assert_eq!(msg_hdr.msg_type, DevMgrMsgType::AddMmio as u32);
            assert_eq!(msg_hdr.msg_size, mem::size_of::<AddMmioDevRequest>() as u32);

            // valid request
            let mmio_dev_req =
                unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut AddMmioDevRequest) };
            assert_eq!(mmio_dev_req, &add_mmio_dev_request);
        }

        // add vcpu dev request
        {
            let cpu_dev_request = CpuDevRequest {
                count: 1,
                apic_ver: 2,
                apic_ids: [3; 256],
            };
            let dev_mgr_request = DevMgrRequest::AddVcpu(cpu_dev_request.clone());
            let buffer = dev_mgr_request.build();

            // valid total size
            assert_eq!(buffer.len(), DEV_MGR_MSG_SIZE);

            // valid header
            let msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
            assert_eq!(msg_hdr.magic_version, DEV_MGR_MAGIC_VERSION);
            assert_eq!(msg_hdr.msg_flags, 0);
            assert_eq!(msg_hdr.msg_type, DevMgrMsgType::AddCpu as u32);
            assert_eq!(msg_hdr.msg_size, mem::size_of::<CpuDevRequest>() as u32);

            // valid request
            let cpu_dev_req = unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevRequest) };
            assert_eq!(cpu_dev_req, &cpu_dev_request);
        }

        // del vcpu dev request
        {
            let cpu_dev_request = CpuDevRequest {
                count: 1,
                apic_ver: 2,
                apic_ids: [3; 256],
            };
            let dev_mgr_request = DevMgrRequest::DelVcpu(cpu_dev_request.clone());
            let buffer = dev_mgr_request.build();

            // valid total size
            assert_eq!(buffer.len(), DEV_MGR_MSG_SIZE);

            // valid header
            let msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
            assert_eq!(msg_hdr.magic_version, DEV_MGR_MAGIC_VERSION);
            assert_eq!(msg_hdr.msg_flags, 0);
            assert_eq!(msg_hdr.msg_type, DevMgrMsgType::DelCpu as u32);
            assert_eq!(msg_hdr.msg_size, mem::size_of::<CpuDevRequest>() as u32);

            // valid request
            let cpu_dev_req = unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevRequest) };
            assert_eq!(cpu_dev_req, &cpu_dev_request);
        }
    }

    #[test]
    fn test_make_dev_mgr_response() {
        let size_hdr = mem::size_of::<DevMgrMsgHeader>();

        // test cpu response
        {
            let buffer = [0; DEV_MGR_MSG_SIZE];
            let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };

            msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;

            msg_hdr.msg_type = DevMgrMsgType::CmdOk as u32;
            msg_hdr.msg_size = mem::size_of::<CpuDevRequest>() as u32;
            msg_hdr.msg_flags = DevMgrMsgType::AddCpu as u32;

            let mut vcpu_result =
                unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevResponse) };
            vcpu_result.apic_id_index = 1;

            match DevMgrResponse::make(&buffer).unwrap() {
                DevMgrResponse::CpuDev(resp) => {
                    assert_eq!(resp.result, true);
                    assert_eq!(resp.info.apic_id_index, 1);
                }
                _ => assert!(false),
            }
        }

        // test add mmio response
        {
            let buffer = [0; DEV_MGR_MSG_SIZE];
            let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };

            msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;

            msg_hdr.msg_type = DevMgrMsgType::CmdOk as u32;
            msg_hdr.msg_size = 0;
            msg_hdr.msg_flags = DevMgrMsgType::AddMmio as u32;

            match DevMgrResponse::make(&buffer).unwrap() {
                DevMgrResponse::AddMmioDev(resp) => {
                    assert_eq!(resp.result, true);
                    assert_eq!(resp.info, ());
                }
                _ => assert!(false),
            }
        }

        // test result error
        {
            let buffer = [0; DEV_MGR_MSG_SIZE];
            let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };

            msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;

            msg_hdr.msg_type = DevMgrMsgType::CmdErr as u32;
            msg_hdr.msg_size = 0;
            msg_hdr.msg_flags = DevMgrMsgType::AddMmio as u32;

            let mut vcpu_result =
                unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevResponse) };
            vcpu_result.apic_id_index = 1;

            match DevMgrResponse::make(&buffer).unwrap() {
                DevMgrResponse::AddMmioDev(resp) => {
                    assert_eq!(resp.result, false);
                    assert_eq!(resp.info, ());
                }
                _ => assert!(false),
            }
        }

        // test invalid unknown msg flag
        {
            let buffer = [0; DEV_MGR_MSG_SIZE];
            let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };

            msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;

            msg_hdr.msg_type = DevMgrMsgType::CmdErr as u32;
            msg_hdr.msg_size = 0;
            msg_hdr.msg_flags = DevMgrMsgType::CmdErr as u32 + 1;

            let mut vcpu_result =
                unsafe { &mut *(buffer[size_hdr..].as_ptr() as *mut CpuDevResponse) };
            vcpu_result.apic_id_index = 1;

            match DevMgrResponse::make(&buffer).unwrap() {
                DevMgrResponse::Other(resp) => {
                    assert_eq!(resp.result, false);
                    assert_eq!(resp.info, ());
                }
                _ => assert!(false),
            }
        }
    }

    fn get_vsock_inner_backend_stream_pair() -> (Box<dyn VsockStream>, Box<dyn VsockStream>) {
        let mut vsock_backend = VsockInnerBackend::new().unwrap();
        let connector = vsock_backend.get_connector();
        let outer_stream = connector.connect().unwrap();
        let inner_stream = vsock_backend.accept().unwrap();

        (inner_stream, outer_stream)
    }

    #[test]
    fn test_dev_mgr_service_connection_start() {
        let (mut inner_stream, mut outer_stream) = get_vsock_inner_backend_stream_pair();
        let dev_mgr_service = DevMgrService {};

        assert!(dev_mgr_service.connection_start(&mut inner_stream).is_ok());
        let mut reader_buf = [0; 2];
        outer_stream.read(&mut reader_buf).unwrap();
        assert_eq!(reader_buf, [b'd', 0]);
    }

    #[test]
    fn test_dev_mgr_service_connection_check() {
        let (mut inner_stream, mut outer_stream) = get_vsock_inner_backend_stream_pair();
        let dev_mgr_service = DevMgrService {};

        // test ok case
        {
            let buffer = [0; DEV_MGR_MSG_SIZE];
            let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
            msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;
            msg_hdr.msg_type = DevMgrMsgType::CmdOk as u32;
            msg_hdr.msg_size = 0;
            msg_hdr.msg_flags = 0;
            inner_stream.write(&buffer).unwrap();

            assert!(dev_mgr_service.connection_check(&mut outer_stream).is_ok());
        }

        // test error case
        {
            let buffer = [0; DEV_MGR_MSG_SIZE];
            let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
            msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;
            msg_hdr.msg_type = DevMgrMsgType::CmdErr as u32;
            msg_hdr.msg_size = 0;
            msg_hdr.msg_flags = 0;
            inner_stream.write(&buffer).unwrap();

            assert!(dev_mgr_service.connection_check(&mut outer_stream).is_err());
        }
    }

    #[test]
    fn test_dev_mgr_service_send_request() {
        let (mut inner_stream, mut outer_stream) = get_vsock_inner_backend_stream_pair();
        let dev_mgr_service = DevMgrService {};

        let add_mmio_dev_request = DevMgrRequest::AddMmioDev(AddMmioDevRequest {
            mmio_base: 0,
            mmio_size: 1,
            mmio_irq: 2,
        });
        let request = UpcallClientRequest::DevMgr(add_mmio_dev_request.clone());

        assert!(dev_mgr_service
            .send_request(&mut outer_stream, request)
            .is_ok());

        let mut reader_buf = [0; DEV_MGR_MSG_SIZE];
        inner_stream.read(&mut reader_buf).unwrap();

        assert!(add_mmio_dev_request
            .build()
            .iter()
            .zip(reader_buf.iter())
            .all(|(req, buf)| req == buf));
    }

    #[test]
    fn test_dev_mgr_service_handle_response() {
        let (mut inner_stream, mut outer_stream) = get_vsock_inner_backend_stream_pair();
        let dev_mgr_service = DevMgrService {};

        let buffer = [0; DEV_MGR_MSG_SIZE];
        let mut msg_hdr = unsafe { &mut *(buffer.as_ptr() as *mut DevMgrMsgHeader) };
        msg_hdr.magic_version = DEV_MGR_MAGIC_VERSION;
        msg_hdr.msg_type = DevMgrMsgType::CmdOk as u32;
        msg_hdr.msg_size = 0;
        msg_hdr.msg_flags = DevMgrMsgType::AddMmio as u32;

        inner_stream.write(&buffer).unwrap();
        assert!(dev_mgr_service.handle_response(&mut outer_stream).is_ok());
    }
}
