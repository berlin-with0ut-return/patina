//! DXE Core Runtime Support
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!
use alloc::collections::BTreeMap;
use core::{
    ffi::c_void,
    mem, ptr,
    sync::atomic::{AtomicBool, Ordering},
};
use mu_pi::{list_entry, protocols::runtime};
use patina_sdk::{base::UEFI_PAGE_SIZE, error::EfiError};
use r_efi::efi;
use spin::Mutex;

use crate::{
    allocator::core_allocate_pool, image::core_relocate_runtime_images, protocols::core_install_protocol_interface,
    systemtables::SYSTEM_TABLE,
};

struct RuntimeData {
    runtime_arch_ptr: *mut runtime::Protocol,
    runtime_images: LinkedList<runtime::ImageEntry, &'static crate::allocator::UefiAllocator>,
    runtime_events: LinkedList<runtime::EventEntry, &'static crate::allocator::UefiAllocator>,
}

unsafe impl Sync for RuntimeData {}
unsafe impl Send for RuntimeData {}

static RUNTIME_DATA: Mutex<RuntimeData> = Mutex::new(RuntimeData::new());
static RUNTIME_EVENTS: Mutex<BTreeMap<usize, crate::event_db::Event, &'static crate::allocator::UefiAllocator>> =
    Mutex::new(BTreeMap::new_in(&crate::allocator::EFI_RUNTIME_SERVICES_DATA_ALLOCATOR));

pub extern "efiapi" fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> efi::Status {
    //
    // Can only switch to virtual addresses once the memory map is locked down,
    // and can only set it once.
    //
    // NOTE: Boot services have been destroyed at this point, this routine must not
    //       call into any other subsystems. Doing so can cause unpredictable behavior.
    //
    {
        let mut runtime_data = RUNTIME_DATA.lock();
        unsafe {
            // Update the image links
            let mut prev = &mut (*self.runtime_arch_ptr).image_head;
            for entry in self.runtime_images.iter_mut() {
                prev.forward_link = (&mut entry.link) as *mut _;
                entry.link.back_link = prev as *mut _;
                prev = &mut entry.link;
            }
            prev.forward_link = &mut (*self.runtime_arch_ptr).image_head as *mut _;
            (*self.runtime_arch_ptr).image_head.back_link = prev as *mut _;

            // Update the event links
            let mut prev = &mut (*self.runtime_arch_ptr).event_head;
            for entry in self.runtime_events.iter_mut() {
                prev.forward_link = (&mut entry.link) as *mut _;
                entry.link.back_link = prev as *mut _;
                prev = &mut entry.link;
            }
            prev.forward_link = &mut (*self.runtime_arch_ptr).event_head as *mut _;
            (*self.runtime_arch_ptr).event_head.back_link = prev as *mut _;
        }
    }

    // TODO: Add status code reporting (need to check runtime eligibility)

    // Signal EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE events (externally registered events)
    for event in RUNTIME_EVENTS.lock().values() {
        if event.event_group() == Some(efi::EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE)
            && let Some(function) = event.notify_fn()
        {
            function(event.efi_event(), event.notify_context().unwrap_or(ptr::null_mut()));
        }
    }

    // Convert runtime images
    core_relocate_runtime_images();

    // Convert runtime services pointers
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().get_time
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().set_time
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().get_wakeup_time
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().set_wakeup_time
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().reset_system
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE
                .lock()
                .as_mut()
                .expect("Invalid system table.")
                .runtime_services_mut()
                .get_next_high_mono_count
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().get_variable
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().set_variable
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().get_next_variable_name
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().query_variable_info
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").runtime_services_mut().update_capsule
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE
                .lock()
                .as_mut()
                .expect("Invalid system table.")
                .runtime_services_mut()
                .query_capsule_capabilities
        ) as *mut *mut c_void,
    );
    SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").checksum_runtime_services();

    // Convert system table runtime fields
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").system_table_mut().firmware_vendor
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").system_table_mut().configuration_table
        ) as *mut *mut c_void,
    );
    convert_pointer(
        0,
        core::ptr::addr_of_mut!(
            SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").system_table_mut().runtime_services
        ) as *mut *mut c_void,
    );
    SYSTEM_TABLE.lock().as_mut().expect("Invalid system table.").checksum();

    {
        let mut runtime_data = RUNTIME_DATA.lock();
        runtime_data.virtual_map = ptr::null_mut();
        runtime_data.virtual_map_index = 0;
    }

    efi::Status::SUCCESS
}

pub fn init_runtime_support(_rt: &mut efi::RuntimeServices) {
    // Setup a event callback for the runtime protocol.
    let event = EVENT_DB
        .create_event(efi::EVT_NOTIFY_SIGNAL, efi::TPL_CALLBACK, Some(runtime_protocol_notify), None, None)
        .expect("Failed to create runtime protocol installation callback.");

    PROTOCOL_DB
        .register_protocol_notify(runtime::PROTOCOL_GUID, event)
        .expect("Failed to register protocol notify on runtime protocol.");
}

pub fn init_runtime_support(rt: &mut efi::RuntimeServices) {
    rt.convert_pointer = convert_pointer;
    rt.set_virtual_address_map = set_virtual_address_map;

    match core_allocate_pool(efi::RUNTIME_SERVICES_DATA, mem::size_of::<runtime::Protocol>()) {
        Err(err) => panic!("Failed to allocate the Runtime Architecture Protocol: {err:?}"),
        Ok(allocation) => unsafe {
            let allocation_ptr = allocation as *mut runtime::Protocol;

            let image_head_ptr = ptr::addr_of_mut!(allocation_ptr.as_mut().unwrap().image_head);
            let event_head_ptr = ptr::addr_of_mut!(allocation_ptr.as_mut().unwrap().event_head);

            allocation_ptr.write(runtime::Protocol {
                // The Rust usage of the protocol won't actually use image_head or event_head,
                // so pass empty linked lists (just heads that point to themselves).
                image_head: list_entry::Entry { forward_link: image_head_ptr, back_link: image_head_ptr },
                event_head: list_entry::Entry { forward_link: event_head_ptr, back_link: event_head_ptr },
                memory_descriptor_size: mem::size_of::<efi::MemoryDescriptor>(), // Should be 16-byte aligned
                memory_descriptor_version: efi::MEMORY_DESCRIPTOR_VERSION,
                memory_map_size: 0,
                memory_map_physical: ptr::null_mut(),
                memory_map_virtual: ptr::null_mut(),
                virtual_mode: AtomicBool::new(false),
                at_runtime: AtomicBool::new(false),
            });
            RUNTIME_DATA.lock().runtime_arch_ptr = allocation_ptr;
            // Install the protocol on a new handle
            core_install_protocol_interface(None, runtime::PROTOCOL_GUID, allocation)
                .expect("Failed to install the Runtime Architecture protocol");
        },
    }
}

pub fn add_runtime_event(event: crate::event_db::Event) -> Result<(), EfiError> {
    let event_id = event.event_id();
    RUNTIME_EVENTS.lock().insert(event_id, event);
    Ok(())
}

pub fn remove_runtime_event(event_id: usize) -> Result<(), EfiError> {
    if RUNTIME_EVENTS.lock().remove(&event_id).is_none() {
        return Err(EfiError::InvalidParameter);
    }
    Ok(())
}

#[cfg(test)]
#[coverage(off)]
mod tests {
    use super::*;
    use crate::test_support;
    use core::{ptr, sync::atomic::AtomicBool};

    fn setup_protocol_and_data() -> RuntimeData {
        let protocol = runtime::Protocol {
            image_head: list_entry::Entry { forward_link: ptr::null_mut(), back_link: ptr::null_mut() },
            event_head: list_entry::Entry { forward_link: ptr::null_mut(), back_link: ptr::null_mut() },
            memory_descriptor_size: 0,
            memory_descriptor_version: 0,
            memory_map_size: 0,
            memory_map_physical: ptr::null_mut(),
            memory_map_virtual: ptr::null_mut(),
            virtual_mode: AtomicBool::new(false),
            at_runtime: AtomicBool::new(false),
        };
        let mut data = RuntimeData::new();
        data.runtime_arch_ptr = Box::leak(Box::new(protocol));
        data
    }

    extern "efiapi" fn dummy_notify(_event: efi::Event, _context: *mut core::ffi::c_void) {
        // Do nothing
    }

    fn new_image(handle: usize) -> runtime::ImageEntry {
        runtime::ImageEntry {
            image_base: ptr::null_mut(),
            image_size: 0,
            relocation_data: ptr::null_mut(),
            handle: handle as efi::Handle,
            link: list_entry::Entry { forward_link: ptr::null_mut(), back_link: ptr::null_mut() },
        }
    }

    fn new_event(event: usize) -> runtime::EventEntry {
        runtime::EventEntry {
            event_type: 0,
            notify_tpl: efi::TPL_APPLICATION,
            notify_function: dummy_notify,
            context: ptr::null_mut(),
            event: event as efi::Event,
            link: list_entry::Entry { forward_link: ptr::null_mut(), back_link: ptr::null_mut() },
        }
    }

    fn with_locked_state<F: Fn() + std::panic::RefUnwindSafe>(f: F) {
        test_support::with_global_lock(|| {
            unsafe {
                crate::test_support::init_test_gcd(None);
                crate::test_support::init_test_protocol_db();
            }
            crate::test_support::reset_dispatcher_context();
            f();
        })
        .unwrap();
    }

    #[test]
    fn test_image_list_consistency() {
        // Runtime tests require global synchronization due to shared static allocators
        // that use TPL locks, which cannot be acquired concurrently
        with_locked_state(|| {
            let mut data = setup_protocol_and_data();
            let link_offset = size_of::<u64>() * 4;

            // Add images
            for i in 0..10 {
                data.runtime_images.push_back(new_image(i));
            }
            data.update_protocol_lists();

            // SAFETY: Parsing a C-style linked list is inherently unsafe, but if the
            //         update_protocol_lists function is correct, this should be safe.
            unsafe {
                // Walk the linked list starting from the head and make sure all entries are present.
                let mut protocol_link = (*data.runtime_arch_ptr).image_head.forward_link;
                let mut count = 0;
                let mut prev = &*(&(*data.runtime_arch_ptr).image_head as *const _) as *const list_entry::Entry;
                while !core::ptr::eq(protocol_link, &mut (*data.runtime_arch_ptr).image_head as *mut _) {
                    let entry = ((protocol_link as *const u8).byte_sub(link_offset) as *const runtime::ImageEntry)
                        .as_ref()
                        .unwrap();
                    assert_eq!(entry.handle as usize, count);
                    assert_eq!(entry.link.back_link, prev as *mut _);
                    count += 1;
                    protocol_link = entry.link.forward_link;
                    prev = &entry.link as *const _;
                    assert!(count <= 10, "Too many entries in the image list.");
                }
                assert_eq!(count, 10, "Not all entries were found in the image list.");
            }

            // Remove all the odd images
            for i in (0..10).filter(|x| x % 2 == 1) {
                for _ in data.runtime_images.extract_if(|entry| entry.handle == i as efi::Handle) {}
            }
            data.update_protocol_lists();

            // SAFETY: Parsing a C-style linked list is inherently unsafe, but if the
            //         update_protocol_lists function is correct, this should be safe.
            unsafe {
                // Walk the linked list starting from the head and make sure all entries are present.
                let mut protocol_link = (*data.runtime_arch_ptr).image_head.forward_link;
                let mut count = 0;
                let mut prev = &*(&(*data.runtime_arch_ptr).image_head as *const _) as *const list_entry::Entry;
                while !core::ptr::eq(protocol_link, &mut (*data.runtime_arch_ptr).image_head as *mut _) {
                    let entry = ((protocol_link as *const u8).byte_sub(link_offset) as *const runtime::ImageEntry)
                        .as_ref()
                        .unwrap();
                    assert_eq!(entry.handle as usize, count * 2);
                    assert_eq!(entry.link.back_link, prev as *mut _);
                    count += 1;
                    protocol_link = entry.link.forward_link;
                    prev = &entry.link as *const _;
                    assert!(count <= 5, "Too many entries in the image list.");
                }
                assert_eq!(count, 5, "Not all entries were found in the image list.");
            }
        });
    }

    #[test]
    fn test_event_list_consistency() {
        // Runtime tests require global synchronization due to shared static allocators
        // that use TPL locks, which cannot be acquired concurrently
        with_locked_state(|| {
            let mut data = setup_protocol_and_data();
            let link_offset = size_of::<u64>() * 5;

            // Add events
            for i in 0..10 {
                data.runtime_events.push_back(new_event(i));
            }
            data.update_protocol_lists();

            // SAFETY: Parsing a C-style linked list is inherently unsafe, but if the
            //         update_protocol_lists function is correct, this should be safe.
            unsafe {
                // Walk the linked list starting from the head and make sure all entries are present.
                let mut protocol_link = (*data.runtime_arch_ptr).event_head.forward_link;
                let mut count = 0;
                let mut prev = &*(&(*data.runtime_arch_ptr).event_head as *const _) as *const list_entry::Entry;
                while !core::ptr::eq(protocol_link, &mut (*data.runtime_arch_ptr).event_head as *mut _) {
                    let entry = ((protocol_link as *const u8).byte_sub(link_offset) as *const runtime::EventEntry)
                        .as_ref()
                        .unwrap();
                    assert_eq!(entry.event as usize, count);
                    assert_eq!(entry.link.back_link, prev as *mut _);
                    count += 1;
                    protocol_link = entry.link.forward_link;
                    prev = &entry.link as *const _;
                    assert!(count <= 10, "Too many entries in the event list.");
                }
                assert_eq!(count, 10, "Not all entries were found in the event list.");
            }

            // Remove all the odd events
            for i in (0..10).filter(|x| x % 2 == 1) {
                for _ in data.runtime_events.extract_if(|entry| entry.event == i as efi::Event) {}
            }
            data.update_protocol_lists();

            // SAFETY: Parsing a C-style linked list is inherently unsafe, but if the
            //         update_protocol_lists function is correct, this should be safe.
            unsafe {
                // Walk the linked list starting from the head and make sure all entries are present.
                let mut protocol_link = (*data.runtime_arch_ptr).event_head.forward_link;
                let mut count = 0;
                let mut prev = &*(&(*data.runtime_arch_ptr).event_head as *const _) as *const list_entry::Entry;
                while !core::ptr::eq(protocol_link, &mut (*data.runtime_arch_ptr).event_head as *mut _) {
                    let entry = ((protocol_link as *const u8).byte_sub(link_offset) as *const runtime::EventEntry)
                        .as_ref()
                        .unwrap();
                    assert_eq!(entry.event as usize, count * 2);
                    assert_eq!(entry.link.back_link, prev as *mut _);
                    count += 1;
                    protocol_link = entry.link.forward_link;
                    prev = &entry.link as *const _;
                    assert!(count <= 5, "Too many entries in the event list.");
                }
                assert_eq!(count, 5, "Not all entries were found in the event list.");
            }
        });
    }
}
