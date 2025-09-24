//! X64 Interrupt manager
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: Apache-2.0
//!

use patina::{
    base::{UEFI_PAGE_MASK, UEFI_PAGE_SIZE},
    component::service::IntoService,
    error::EfiError,
    pi::protocols::cpu_arch::EfiSystemContext,
};
use patina_mtrr::Mtrr;
use patina_paging::{PageTable, PagingType};
use patina_stacktrace::{StackFrame, StackTrace};

use crate::interrupts::{EfiExceptionStackTrace, HandlerType, InterruptManager, x64::ExceptionContextX64};

/// X64 Implementation of the InterruptManager.
///
/// An x64 version of the InterruptManager for managing IDT based interrupts.
///
#[derive(Default, Copy, Clone, IntoService)]
#[service(dyn InterruptManager)]
pub struct InterruptsX64 {}

impl InterruptsX64 {
    /// Creates a new instance of the x64 implementation of the InterruptManager.
    pub const fn new() -> Self {
        Self {}
    }

    /// Initializes the hardware and software structures for interrupts and exceptions.
    ///
    /// This routine will initialize the architecture and platforms specific mechanisms
    /// for interrupts and exceptions to be taken. This routine may install some
    /// architecture specific default handlers for exceptions.
    ///
    pub fn initialize(&mut self) -> Result<(), EfiError> {
        // Initialize the IDT.
        #[cfg(target_os = "uefi")]
        crate::interrupts::x64::idt::initialize_idt();

        // Register some default handlers.
        self.register_exception_handler(13, HandlerType::UefiRoutine(general_protection_fault_handler))
            .expect("Failed to install default exception handler!");
        self.register_exception_handler(14, HandlerType::UefiRoutine(page_fault_handler))
            .expect("Failed to install default exception handler!");

        Ok(())
    }
}

impl InterruptManager for InterruptsX64 {}

/// Handler for double faults.
///
/// Handler for doubel faults that is configured to run as a direct interrupt
/// handler without using the normal handler assembly or stack. This is done to
/// increase the diagnosability of faults in the interrupt handling code.
///
extern "x86-interrupt" fn double_fault_handler(stack_frame: InterruptStackFrame, _error_code: u64) -> ! {
    panic!("EXCEPTION: DOUBLE FAULT\n{stack_frame:#x?}");
}

/// Default handler for GP faults.
extern "efiapi" fn general_protection_fault_handler(_exception_type: isize, context: EfiSystemContext) {
    // SAFETY: We don't have any choice here, we are in an exception and have to do our best
    // to report. The system is dead anyway.
    let x64_context = unsafe { context.system_context_x64.as_ref().unwrap() };
    log::error!("EXCEPTION: GP FAULT");
    log::error!("Instruction Pointer: {:#X?}", x64_context.rip);
    log::error!("Code Segment: {:#X?}", x64_context.cs);
    log::error!("RFLAGS: {:#X?}", x64_context.rflags);
    log::error!("Stack Segment: {:#X?}", x64_context.ss);
    log::error!("Stack Pointer: {:#X?}", x64_context.rsp);
    log::error!("Data Segment: {:#X?}", x64_context.ds);
    log::error!("Paging Enable: {}", x64_context.cr0 & 0x80000000 != 0);
    log::error!("Protection Enable: {}", x64_context.cr0 & 0x00000001 != 0);
    log::error!("Page Directory Base: {:#X?}", x64_context.cr3);
    log::error!("Control Flags (cr4): {:#X?}", x64_context.cr4);
    interpret_gp_fault_exception_data(x64_context.exception_data);

    log::error!("");

    log::debug!("Full Context: {x64_context:#x?}");

    if let Err(err) = unsafe { StackTrace::dump_with(x64_context.rip, x64_context.rsp) } {
        log::error!("StackTrace: {err}");
    }

    panic!("EXCEPTION: GP FAULT");
}

#[coverage(off)]
/// Default handler for page faults.
extern "efiapi" fn page_fault_handler(_exception_type: isize, context: EfiSystemContext) {
    // SAFETY: We don't have any choice here, we are in an exception and have to do our best
    // to report. The system is dead anyway.
    let x64_context = unsafe { context.system_context_x64.as_ref().unwrap() };

    log::error!("EXCEPTION: PAGE FAULT");
    log::error!("Accessed Address: {:#X?}", x64_context.cr2);
    log::error!("Paging Enabled: {}", x64_context.cr0 & 0x80000000 != 0);
    log::error!("Instruction Pointer: {:#X?}", x64_context.rip);
    log::error!("Code Segment: {:#X?}", x64_context.cs);
    log::error!("RFLAGS: {:#X?}", x64_context.rflags);
    log::error!("Stack Segment: {:#X?}", x64_context.ss);
    log::error!("Data Segment: {:#X?}", x64_context.ds);
    log::error!("Stack Pointer: {:#X?}", x64_context.rsp);
    log::error!("Page Directory Base: {:#X?}", x64_context.cr3);
    log::error!("Paging Features (cr4): {:#X?}", x64_context.cr4);
    interpret_page_fault_exception_data(x64_context.exception_data);

    log::error!("");

    (x64_context as &ExceptionContextX64).dump_system_context_registers();

    let paging_type =
        { if x64_context.cr4 & (1 << 12) != 0 { PagingType::Paging5Level } else { PagingType::Paging4Level } };

    if let Some(attrs) = get_fault_attributes(x64_context.cr2, x64_context.cr3, paging_type) {
        log::error!("Page Attributes: {attrs:?}");
    }

    log::error!(
        "General-Purpose Registers\n \
                RAX: {:x?}\n \
                RBX: {:x?}\n \
                RCX: {:x?}\n \
                RDX: {:x?}\n \
                RSI: {:x?}\n \
                RDI: {:x?}\n \
                RBP: {:x?}\n \
                R8: {:x?}\n \
                R9: {:x?}\n \
                R10: {:x?}\n \
                R11: {:x?}\n \
                R12: {:x?}\n \
                R13: {:x?}\n \
                R14: {:x?}\n \
                R15: {:x?}",
        x64_context.rax,
        x64_context.rbx,
        x64_context.rcx,
        x64_context.rdx,
        x64_context.rsi,
        x64_context.rdi,
        x64_context.rbp,
        x64_context.r8,
        x64_context.r9,
        x64_context.r10,
        x64_context.r11,
        x64_context.r12,
        x64_context.r13,
        x64_context.r14,
        x64_context.r15
    );

    log::debug!("Full Context: {x64_context:#x?}");

    if let Err(err) = unsafe { StackTrace::dump_with(x64_context.rip, x64_context.rsp) } {
        log::error!("StackTrace: {err}");
    }

    panic!("EXCEPTION: PAGE FAULT");
}

/// Gets the address of the assembly entry point for the given vector index.
fn get_vector_address(index: usize) -> VirtAddr {
    // Verify the index is in [0-255]
    if index >= 256 {
        panic!("Invalid vector index! 0x{index:x}");
    }

    unsafe { VirtAddr::from_ptr(AsmGetVectorAddress(index) as *const ()) }
}

fn interpret_page_fault_exception_data(exception_data: u64) {
    log::error!("Error Code: 0x{exception_data:x}\n");
    if (exception_data & 0x1) == 0 {
        log::error!("Page not present");
    } else {
        log::error!("Page-level protection violation");
    }

    if (exception_data & 0x2) == 0 {
        log::error!("R/W: Read");
    } else {
        log::error!("R/W: Write");
    }

    if (exception_data & 0x4) == 0 {
        log::error!("Mode: Supervisor");
    } else {
        log::error!("Mode: User");
    }

    if (exception_data & 0x8) == 0 {
        log::error!("Reserved bit violation");
    }

    if (exception_data & 0x10) == 0 {
        log::error!("Instruction fetch access");
    }
}

// There is no value in coverage for this function.
#[coverage(off)]
fn interpret_gp_fault_exception_data(exception_data: u64) {
    log::error!("Error Code: 0x{exception_data:x}\n");
    if (exception_data & 0x1) != 0 {
        log::error!("Invalid segment");
    }

    if (exception_data & 0x2) != 0 {
        log::error!("Invalid write access");
    }

    if (exception_data & 0x4) == 0 {
        log::error!("Mode: Supervisor");
    } else {
        log::error!("Mode: User");
    }
}

// There is no value in coverage for this function.
#[coverage(off)]
/// Dumps the page table entries for the given CR2 and CR3 values.
///
/// ## Safety
///
/// The caller is responsible for ensuring that the CR3 value is a valid and well-formed page table base address and
/// matches the paging type requested.
unsafe fn dump_pte(cr2: u64, cr3: u64, paging_type: PagingType) {
    // SAFETY: Caller must ensure cr3 & paging type are correct.
    if let Ok(pt) = unsafe {
        patina_paging::x64::X64PageTable::from_existing(
            cr3,
            patina_paging::page_allocator::PageAllocatorStub,
            paging_type,
        )
    } {
        let _ = pt.dump_page_tables(cr2 & !(UEFI_PAGE_MASK as u64), UEFI_PAGE_SIZE as u64);
    }

    // we don't carry the caching attributes in the page table, so get them from the MTRRs
    let mtrr = patina_mtrr::create_mtrr_lib(0);
    log::error!("");
    log::error!("MTRR Cache Attribute: {}", mtrr.get_memory_attribute(cr2));
    log::error!("");
}

#[coverage(off)]
#[cfg(test)]
mod test {
    extern crate std;

    use serial_test::serial;

    use super::*;

    #[test]
    #[serial(exception_handlers)]
    fn test_interrupts_x64() {
        let mut interrupts = InterruptsX64::new();
        assert!(interrupts.initialize().is_ok());
        assert!(interrupts.unregister_exception_handler(13).is_ok());
        assert!(interrupts.unregister_exception_handler(14).is_ok());
    }
}
