//! Process management syscalls
//!
use crate::config::PAGE_SIZE;
use crate::mm::{translated_byte_buffer, MapPermission, PTEFlags, PageTable, VirtAddr};
use crate::task::TaskControlBlock;
use crate::timer::get_time_us;
use alloc::sync::Arc;
use core::mem::size_of;

use crate::{
    fs::{open_file, OpenFlags},
    mm::{translated_refmut, translated_str},
    task::{
        add_task, current_task, current_user_token, exit_current_and_run_next,
        suspend_current_and_run_next,
    },
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// Check the entire user buffer before writing through the kernel mapping.
pub(super) fn user_range_accessible(token: usize, start: usize, len: usize, permission: PTEFlags) -> bool {
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

pub fn sys_exit(exit_code: i32) -> ! {
    trace!("kernel:pid[{}] sys_exit", current_task().unwrap().pid.0);
    exit_current_and_run_next(exit_code);
    panic!("Unreachable in sys_exit!");
}

pub fn sys_yield() -> isize {
    //trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

pub fn sys_getpid() -> isize {
    trace!("kernel: sys_getpid pid:{}", current_task().unwrap().pid.0);
    current_task().unwrap().pid.0 as isize
}

pub fn sys_fork() -> isize {
    trace!("kernel:pid[{}] sys_fork", current_task().unwrap().pid.0);
    let current_task = current_task().unwrap();
    let new_task = current_task.fork();
    let new_pid = new_task.pid.0;
    // modify trap context of new_task, because it returns immediately after switching
    let trap_cx = new_task.inner_exclusive_access().get_trap_cx();
    // we do not have to move to next instruction since we have done it before
    // for child process, fork returns 0
    trap_cx.x[10] = 0;
    // add new task to scheduler
    add_task(new_task);
    new_pid as isize
}

pub fn sys_exec(path: *const u8) -> isize {
    trace!("kernel:pid[{}] sys_exec", current_task().unwrap().pid.0);
    let token = current_user_token();
    let path = translated_str(token, path);
    if let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) {
        let all_data = app_inode.read_all();
        let task = current_task().unwrap();
        task.exec(all_data.as_slice());
        0
    } else {
        -1
    }
}

/// If there is not a child process whose pid is same as given, return -1.
/// Else if there is a child process but it is still running, return -2.
pub fn sys_waitpid(pid: isize, exit_code_ptr: *mut i32) -> isize {
    //trace!("kernel: sys_waitpid");
    let task = current_task().unwrap();
    // find a child process

    // ---- access current PCB exclusively
    let mut inner = task.inner_exclusive_access();
    if !inner
        .children
        .iter()
        .any(|p| pid == -1 || pid as usize == p.getpid())
    {
        return -1;
        // ---- release current PCB
    }
    let pair = inner.children.iter().enumerate().find(|(_, p)| {
        // ++++ temporarily access child PCB exclusively
        p.inner_exclusive_access().is_zombie() && (pid == -1 || pid as usize == p.getpid())
        // ++++ release child PCB
    });
    if let Some((idx, _)) = pair {
        let child = inner.children.remove(idx);
        // confirm that child will be deallocated after being removed from children list
        assert_eq!(Arc::strong_count(&child), 1);
        let found_pid = child.getpid();
        // ++++ temporarily access child PCB exclusively
        let exit_code = child.inner_exclusive_access().exit_code;
        // ++++ release child PCB
        *translated_refmut(inner.memory_set.token(), exit_code_ptr) = exit_code;
        found_pid as isize
    } else {
        -2
    }
    // ---- release current PCB automatically
}

/// Write the current time to a validated user buffer, including across pages.
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

/// Allocate user pages with the requested R/W/X permissions.
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap");
    if start % PAGE_SIZE != 0 || port == 0 || port & !0x7 != 0 {
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

/// Release an aligned range of owned user pages.
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
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
    trace!("kernel:pid[{}] sys_sbrk", current_task().unwrap().pid.0);
    if let Some(old_brk) = current_task().unwrap().change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}

/// Create a child directly from an executable stored in easy-fs.
pub fn sys_spawn(path: *const u8) -> isize {
    let token = current_user_token();
    let path = translated_str(token, path);

    let Some(app_inode) = open_file(path.as_str(), OpenFlags::RDONLY) else {
        return -1;
    };
    let elf_data = app_inode.read_all();

    let parent = current_task().unwrap();
    let child = Arc::new(TaskControlBlock::new(elf_data.as_slice()));
    let child_pid = child.getpid();
    {
        let mut child_inner = child.inner_exclusive_access();
        child_inner.parent = Some(Arc::downgrade(&parent));
    }
    {
        let mut parent_inner = parent.inner_exclusive_access();
        parent_inner.children.push(Arc::clone(&child));
    }
    add_task(child);
    child_pid as isize
}

/// Set scheduling priority; values below 2 are invalid.
pub fn sys_set_priority(prio: isize) -> isize {
    if prio < 2 {
        return -1;
    }
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    inner.priority = prio as usize;
    prio
}
