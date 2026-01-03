use ghostptr::{Handle, NtStatus};
use core::ffi::c_void;

pub const WORKER_FACTORY_ALL_ACCESS: u32 =
    0 | 0xF0000 | 0x00001 | 0x00002 | 0x00004 | 0x00008 | 0x00010 | 0x00020;

unsafe extern "system" {
	pub fn NtSetIoCompletion(
		io_completion_handle: Handle,
		key_context: *const c_void,
		apc_context: *const c_void,
		io_status: NtStatus,
		io_status_info: usize,
	) -> NtStatus;

    pub fn NtQueryInformationWorkerFactory(
        handle: Handle,
        info_class: u32,
        info: *mut c_void,
        info_len: u32,
        return_len: *mut u32,
    ) -> NtStatus;

    pub fn NtSetInformationWorkerFactory(
        handle: Handle,
        info_class: u32,
        info: *const c_void,
        info_len: u32,
    ) -> NtStatus;
}

#[repr(C)]
pub struct WorkerFactoryBasicInformation {
    pub timeout: u64,
    pub retry_timeout: u64,
    pub idle_timeout: u64,
    pub paused: u8,
    pub timer_set: u8,
    pub queued_to_ex_worker: u8,
    pub may_create: u8,
    pub create_in_progress: u8,
    pub inserted_into_queue: u8,
    pub shutdown: u8,
    pub _padding1: u8,
    pub binding_count: u32,
    pub thread_minimum: u32,
    pub thread_maximum: u32,
    pub pending_worker_count: u32,
    pub waiting_worker_count: u32,
    pub total_worker_count: u32,
    pub release_count: u32,
    pub infinite_wait_goal: i64,
    pub start_routine: *mut c_void,
    pub start_parameter: *mut c_void,
    pub process_id: usize,
    pub stack_reserve: usize,
    pub stack_commit: usize,
    pub last_thread_creation_status: i32,
}

#[repr(C)]
pub struct ListEntry {
	pub next: *const ListEntry,
	pub prev: *const ListEntry,
}

#[repr(C)]
pub struct TpTaskCallbacks {
	pub execute_callback: *const c_void,
	pub unposted: *const c_void,
}

#[repr(C)]
pub struct TpTask {
	pub callbacks: *const TpTaskCallbacks,
	pub numa_node: u32,
	pub ideal_processor: u8,
	padding: [u8; 3],
	pub list_entry: ListEntry,
}

#[repr(C)]
pub struct TpDirect {
	pub task: TpTask,
	pub lock: u64,
	pub io_completion_information_list: ListEntry,
	pub callback: *const c_void,
	pub numa_node: u32,
	pub ideal_processor: u8,
	pub padding: [u8; 3]
}

// #define IO_COMPLETION_ALL_ACCESS (IO_COMPLETION_QUERY_STATE|IO_COMPLETION_MODIFY_STATE|STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE)
pub const IO_COMPLETION_ALL_ACCESS: u32 = 0
	| 0x000001 // IO_COMPLETION_QUERY_STATE
	| 0x000002 // IO_COMPLETION_MODIFY_STATE
	| 0x0F0000 // STANDARD_RIGHTS_REQUIRED
	| 0x100000; // SYNCHRONIZE