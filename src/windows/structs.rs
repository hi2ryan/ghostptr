use core::ffi::c_void;

use crate::windows::{DllEntryPoint, Handle, NtStatus};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListEntry {
    pub next: *const ListEntry,
    pub prev: *const ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub max_length: u16,
    pub buffer: *const u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LoaderDataTableEntry {
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
    pub base_address: *mut u8,
    pub entry_point: *const DllEntryPoint,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
    pub hash_table_entry: ListEntry,
    pub time_datestamp: u32,
    pub entry_point_activation_context: *const c_void,
    pub lock: *const c_void,
    pub ddag_node: *const c_void,
    pub node_module_link: ListEntry,
    pub load_context: *const c_void,
    pub parent_dll_base: *const c_void,
    pub switch_back_context: *const c_void,
    pub base_address_index_node: RtlBalancedNode,
    pub mapping_info_index_node: RtlBalancedNode,
    pub original_base: *const c_void,
    pub load_time: i64,
    pub base_name_hash_value: u32,
    pub load_reason: LdrDllLoadReason,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlBalancedNode {
    pub left: *const RtlBalancedNode,
    pub right: *const RtlBalancedNode,
    pub parent_value: usize,
}

#[repr(i32)]
#[derive(Clone, Copy)]
pub enum LdrDllLoadReason {
    Unknown = -1,
    StaticDependency = 0,
    StaticForwarderDependency = 1,
    DynamicForwarderDependency = 2,
    DelayloadDependency = 3,
    DynamicLoad = 4,
    AsImageLoad = 5,
    AsDataLoad = 6,
    EnclavePrimary = 7,
    EnclaveDependency = 8,
    PatchImage = 9,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PebLoaderData {
    length: u32,
    initialized: u8,
    ss_handle: *mut c_void,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEnvBlock {
    reserved1: [u8; 2],
    pub being_debugged: u8,
    reserved2: [u8; 1],
    reserved3: [*const c_void; 2],
    pub ldr: *const PebLoaderData, // +0x18
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRegistrationRecord {
    pub next: *mut ExceptionRegistrationRecord,
    pub handler: usize, // supposed to be a function
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TibData {
    fiber_data: *mut c_void,
    version: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadInfoBlock {
    // NT_TIB
    pub exception_list: *mut ExceptionRegistrationRecord,
    pub stack_base: *mut c_void,
    pub stack_limit: *mut c_void,
    pub sub_system_tib: *mut c_void,
    pub data: TibData,
    pub arbitrary_user_pointer: *mut c_void,
    pub self_: *mut ThreadEnvBlock,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadEnvBlock {
    pub tib: *const ThreadInfoBlock,
    pub environment_pointer: *const c_void,
    pub client_id: ClientId,
}

#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ImageNtHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ImageSectionHeaderMisc {
    pub physical_address: u32,
    pub virtual_size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub misc: ImageSectionHeaderMisc,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Initialized = 0,
    Ready = 1,
    Running = 2,
    Standby = 3,
    Terminated = 4,
    Waiting = 5,
    Transition = 6,
    DeferredReady = 7,
    GateWait = 8,
    WaitingForProcessInSwap = 9,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadWaitReason {
    Executive = 0,
    FreePage = 1,
    PageIn = 2,
    PoolAllocation = 3,
    DelayExecution = 4,
    Suspended = 5,
    UserRequest = 6,
    WrExecutive = 7,
    WrFreePage = 8,
    WrPageIn = 9,
    WrPoolAllocation = 10,
    WrDelayExecution = 11,
    WrSuspended = 12,
    WrUserRequest = 13,
    WrEventPair = 14,
    WrQueue = 15,
    WrLpcReceive = 16,
    WrLpcReply = 17,
    WrVirtualMemory = 18,
    WrPageOut = 19,
    WrRendezvous = 20,
    WrKeyedEvent = 21,
    WrTerminated = 22,
    WrProcessInSwap = 23,
    WrCpuRateControl = 24,
    WrCalloutStack = 25,
    WrKernel = 26,
    WrResource = 27,
    WrPushLock = 28,
    WrMutex = 29,
    WrQuantumEnd = 30,
    WrDispatchInt = 31,
    WrPreempted = 32,
    WrYieldExecution = 33,
    WrFastMutex = 34,
    WrGuardedMutex = 35,
    WrRundown = 36,
    WrAlertByThreadId = 37,
    WrDeferredPreempt = 38,
    WrPhysicalFault = 39,
    WrIoRing = 40,
    WrMdlCache = 41,
    WrRcu = 42,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SystemThreadInformation {
    pub kernel_time: i64,
    pub user_time: i64,
    pub create_time: i64,
    pub wait_time: u32,
    pub start_address: *mut c_void,
    pub client_id: ClientId,
    pub priority: i32,
    pub base_priority: i32,
    pub context_switches: u32,
    pub state: ThreadState,
    pub wait_reason: ThreadWaitReason,
}

#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: u32,
    pub number_of_threads: u32,
    pub working_set_private_size: u64,
    pub hard_fault_count: u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time: u64,
    pub create_time: i64,
    pub user_time: i64,
    pub kernel_time: i64,
    pub image_name: UnicodeString,
    pub base_priority: i32,
    pub unique_process_id: Handle,
    pub inherited_from_unique_process_id: Handle,
    pub handle_count: u32,
    pub session_id: u32,
    pub unique_process_key: usize,
    pub peak_virtual_size: usize,
    pub virtual_size: usize,
    pub page_fault_count: u32,
    pub peak_working_set_size: usize,
    pub working_set_size: usize,
    pub quota_peak_paged_pool_usage: usize,
    pub quota_paged_pool_usage: usize,
    pub quota_peak_non_paged_pool_usage: usize,
    pub quota_non_paged_pool_usage: usize,
    pub pagefile_usage: usize,
    pub peak_pagefile_usage: usize,
    pub private_page_count: usize,
    pub read_operation_count: i64,
    pub write_operation_count: i64,
    pub other_operation_count: i64,
    pub read_transfer_count: i64,
    pub write_transfer_count: i64,
    pub other_transfer_count: i64,
    pub threads: [SystemThreadInformation; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ClientId {
    pub unique_process: usize,
    pub unique_thread: usize,
}

#[repr(C)]
pub struct ObjectAttributes {
    pub length: u32,
    pub root_directory: usize,
    pub object_name: *mut UnicodeString, // PUNICODE_STRING
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadBasicInformation {
    pub exit_status: NtStatus,
    pub teb_base_address: *const ThreadEnvBlock,
    pub client_id: ClientId,
    pub affinity_mask: usize,
    pub priority: i32,
    pub base_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessBasicInformation {
    pub exit_status: NtStatus,
    pub peb_base_address: *const ProcessEnvBlock,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub pid: usize,
    pub inherited_from_pid: usize,
}

/*
typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID  BaseAddress;
    PVOID  AllocationBase;
    ULONG  AllocationProtect;
    USHORT PartitionId;
    SIZE_T RegionSize;
    ULONG  State;
    ULONG  Protect;
    ULONG  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
*/

#[repr(C)]
pub struct MemoryBasicInformation {
    pub base_address: *const c_void,
    pub allocation_base: *const c_void,
    pub allocation_protection: u32,
    pub partition_id: u16,
    pub region_size: usize,
    pub state: u32,
    pub protection: u32,
    pub mem_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessHandleEntry {
    pub handle: Handle,
    pub count: usize,
    pub pointer_count: usize,
    pub access: u32,
    pub object_type_index: u32,
    pub handle_attributes: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessHandleSnapshotInformation {
    pub handle_count: usize,
    reserved: usize,
    pub handles: [ProcessHandleEntry; 1],
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug)]
pub struct M128A {
    pub low: u64,
    pub high: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct XSaveFormat {
    pub control_word: u16,
    pub status_word: u16,
    pub tag_word: u8,
    pub reserved1: u8,
    pub error_opcode: u16,
    pub error_offset: u32,
    pub error_selector: u16,
    pub reserved2: u16,
    pub data_offset: u32,
    pub data_selector: u16,
    pub reserved3: u16,
    pub mx_csr: u32,
    pub mx_csr_mask: u32,
    pub float_registers: [M128A; 8],
    pub xmm_registers: [M128A; 16],
    pub reserved4: [u8; 96],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ContextXmmLayout {
    pub header: [M128A; 2],
    pub legacy: [M128A; 8],
    pub xmm0: M128A,
    pub xmm1: M128A,
    pub xmm2: M128A,
    pub xmm3: M128A,
    pub xmm4: M128A,
    pub xmm5: M128A,
    pub xmm6: M128A,
    pub xmm7: M128A,
    pub xmm8: M128A,
    pub xmm9: M128A,
    pub xmm10: M128A,
    pub xmm11: M128A,
    pub xmm12: M128A,
    pub xmm13: M128A,
    pub xmm14: M128A,
    pub xmm15: M128A,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ContextXmmState {
    pub flt_save: XSaveFormat,
    pub xmm: ContextXmmLayout,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadContext {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub eflags: u32,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub xmm_state: ContextXmmState,
    pub vector_register: [M128A; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PublicObjectTypeInformation {
    pub type_name: UnicodeString,
    pub reserved: [u32; 22],
}

#[repr(C)]
pub struct PsAttribute {
    pub attribute: usize,
    pub size: usize,

    pub value: usize,

    pub return_length: *mut usize,
}

#[repr(C)]
pub struct PsAttributeList {
    pub total_length: usize,
    pub attributes: [PsAttribute; 1],
}

#[repr(C)]
pub struct ObjectBasicInformation {
    pub attributes: u32,
    pub granted_access: u32,
    pub handle_count: u32,
    pub pointer_count: u32,
    pub paged_pool_charge: u32,
    pub non_paged_pool_charge: u32,
    pub reserved: [u32; 3],
    pub name_info_size: u32,
    pub type_info_size: u32,
    pub security_descriptor_size: u32,
    pub creation_time: u64,
}

#[repr(C)]
pub struct KernelUserTimes {
    pub create_time: i64,
    pub exit_time: i64,
    pub kernel_time: i64,
    pub user_time: i64,
}

#[repr(C)]
pub struct RtlProcessModules {
    pub count: u32,
    pub modules: [RtlProcessModuleInformation; 1],
}

#[repr(C)]
pub struct RtlProcessModuleInformation {
    pub section: *mut c_void,
    pub mapped_base: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u32,
    pub flags: u32,
    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,
    pub full_path_name: [u8; 256],
}

#[repr(C)]
pub struct SystemHandleTableEntryInfoEx {
    pub object: usize,
    pub unique_process_id: usize,
    pub handle_value: usize,
    pub granted_access: u32,
    pub creator_backtrace_index: u16,
    pub object_type_index: u16,
    pub handle_attributes: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SystemHandleInformationEx {
    pub number_of_handles: usize,
    pub reserved: usize,
    pub handles: [SystemHandleTableEntryInfoEx; 1],
}

#[repr(C)]
pub struct ProcessInstrumentationCallbackInfo {
    pub version: u32,
    pub reserved: u32,
    pub callback: *mut c_void,
}

#[repr(C)]
pub struct TokenPrivileges {
    pub privilege_count: u32,
    pub privileges: [LuidAndAttributes; 1],
}

#[repr(C)]
pub struct LuidAndAttributes {
    pub luid: Luid,
    pub attributes: u32,
}

#[repr(C)]
pub struct Luid {
    pub low_part: u32,
    pub high_part: i32,
}

#[repr(C)]
pub struct SRWLock {
    pub value: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlVectorHandlerList {
    pub veh_lock: *const SRWLock,
    pub veh_list: ListEntry,

    pub vch_lock: *const SRWLock,
    pub vch_list: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlVectorHandlerEntry {
    pub list: ListEntry,
    pub ref_count: *mut u64,
    pub zero: u32,
    pub padding: u32,
    pub encoded_handler: *mut c_void,
}

#[repr(C)]
pub struct ExceptionPointers {
    pub exception_record: *mut ExceptionRecord,
    pub context_record: *mut ThreadContext,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRecord {
    pub exception_code: NtStatus,
    pub exception_flags: u32,
    pub exception_record: *mut ExceptionRecord,
    pub exception_address: *mut core::ffi::c_void,
    pub number_parameters: u32,
    pub exception_information: [usize; 15],
}
