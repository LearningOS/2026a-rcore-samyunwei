//! Process management syscalls
use crate::config::PAGE_SIZE;
use crate::mm::{translated_byte_buffer, MapPermission, PTEFlags, PageTable, VirtAddr};
use crate::task::{
    change_program_brk, current_user_token, exit_current_and_run_next, suspend_current_and_run_next,
};
use crate::timer::get_time_us;
use core::mem::size_of;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Check every page before accessing user memory through the kernel mapping.
fn user_range_accessible(token: usize, start: usize, len: usize, permission: PTEFlags) -> bool {
    let Some(end) = start.checked_add(len) else {
        return false;
    };
    let page_table = PageTable::from_token(token);
    let required = PTEFlags::V | PTEFlags::U | permission;
    let mut address = start;
    while address < end {
        let va = VirtAddr::from(address);
        // VirtAddr::from truncates high bits; reject noncanonical Sv39 addresses.
        if usize::from(va) != address {
            return false;
        }
        let Some(pte) = page_table.translate(va.floor()) else {
            return false;
        };
        if !pte.flags().contains(required) {
            return false;
        }
        address += (end - address).min(PAGE_SIZE - va.page_offset());
    }
    true
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// Write seconds and microseconds to user memory, including across page boundaries.
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let us = get_time_us();
    let sec = us / 1_000_000;
    let usec = us % 1_000_000;

    let word_size = size_of::<usize>();
    let mut bytes = [0u8; 2 * size_of::<usize>()];

    bytes[..word_size].copy_from_slice(&sec.to_ne_bytes());
    bytes[word_size..].copy_from_slice(&usec.to_ne_bytes());

    let token = current_user_token();
    // Validate the whole structure before writing any of its bytes.
    if !user_range_accessible(token, ts as usize, bytes.len(), PTEFlags::W) {
        return -1;
    }
    let buffers = translated_byte_buffer(token, ts as *const u8, bytes.len());

    let mut offset = 0;
    for buffer in buffers {
        let len = buffer.len();
        buffer.copy_from_slice(&bytes[offset..offset + len]);
        offset += len;
    }
    0
}

/// Read/write one user byte, or query the current task's syscall count.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    match trace_request {
        0 => {
            let token = current_user_token();
            if !user_range_accessible(token, id, 1, PTEFlags::R) {
                return -1;
            }
            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            buffers[0][0] as isize
        }
        1 => {
            let token = current_user_token();
            if !user_range_accessible(token, id, 1, PTEFlags::W) {
                return -1;
            }
            let mut buffers = translated_byte_buffer(token, id as *const u8, 1);
            buffers[0][0] = data as u8;
            0
        }
        2 => crate::task::get_current_syscall_count(id) as isize,
        _ => -1,
    }
}

/// Allocate user pages at an aligned address with the requested R/W/X permissions.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if start % PAGE_SIZE != 0 || port == 0 || port & !0x7!= 0 {
        return -1;
    }
    let start_va = VirtAddr::from(start);
    if usize::from(start_va) != start {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = start.checked_add(len) else {
        return -1;
    };
    // Reject noncanonical addresses and ranges crossing the Sv39 address hole.
    let last = end - 1;
    if usize::from(VirtAddr::from(last)) != last || start >> 38 != last >> 38 {
        return -1;
    }

    let mut permission = MapPermission::U;
    if port & 0b001 != 0 {
        permission |= MapPermission::R;
    }
    if port & 0b010 != 0 {
        permission |= MapPermission::W;
    }
    if port & 0b100 != 0 {
        permission |= MapPermission::X;
    }
    if crate::task::mmap_current(start_va, VirtAddr::from(end), permission) {
        0
    } else {
        -1
    }
}

// YOUR JOB: Implement munmap.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap NOT IMPLEMENTED YET!");
     if start % PAGE_SIZE != 0 {
        return -1;
    }
    let start_va = VirtAddr::from(start);
    if usize::from(start_va) != start {
        return -1;
    }
    if len == 0 {
        return 0;
    }
    let Some(end) = start.checked_add(len) else {
        return -1;
    };
    // Reject noncanonical addresses and ranges crossing the Sv39 address hole.
    let last = end - 1;
    if usize::from(VirtAddr::from(last)) != last || start >> 38 != last >> 38 {
        return -1;
    }
    if crate::task::munmap_current(start_va, len) {
        0
    } else {
        -1
    }
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
