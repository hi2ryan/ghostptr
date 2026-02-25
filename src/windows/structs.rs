use core::ptr;

use crate::windows::{DllEntryPoint, Handle, NtStatus};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListEntry {
    pub next: *mut ListEntry,
    pub prev: *mut ListEntry,
}

impl Default for ListEntry {
    fn default() -> Self {
        Self {
            next: ptr::null_mut(),
            prev: ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UnicodeString {
    pub length: u16,
    pub max_length: u16,
    pub buffer: *mut u16,
}

impl Default for UnicodeString {
    fn default() -> Self {
        Self {
            length: 0,
            max_length: 0,
            buffer: ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LoaderDataTableEntry {
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
    pub base_address: *mut u8,
    pub entry_point: Option<DllEntryPoint>,
    pub size_of_image: u32,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: u32,
    pub load_count: u16,
    pub tls_index: u16,
    pub hash_table_entry: ListEntry,
    pub time_datestamp: u32,
    pub entry_point_activation_context: *mut (),
    pub lock: *mut (),
    pub ddag_node: *mut (),
    pub node_module_link: ListEntry,
    pub load_context: *mut (),
    pub parent_dll_base: *mut (),
    pub switch_back_context: *mut (),
    pub base_address_index_node: RtlBalancedNode,
    pub mapping_info_index_node: RtlBalancedNode,
    pub original_base: *mut (),
    pub load_time: i64,
    pub base_name_hash_value: u32,
    pub load_reason: LdrDllLoadReason,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlBalancedNode {
    pub left: *mut RtlBalancedNode,
    pub right: *mut RtlBalancedNode,
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
    pub length: u32,
    pub initialized: u8,
    pub ss_handle: *mut (),
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
    pub entry_in_progress: *mut (),
    pub shutdown_in_progress: u8,
    pub shutdown_thread_id: Handle,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEnvBlock {
    /// Whether the process was cloned with an inherited address space.
    pub inherited_address_space: u8,

    /// Determines if the process has image file execution options (IFEO).
    pub read_image_file_exec_options: u8,

    /// Whether the the process has a debugger attached or not.
    pub being_debugged: u8,

    pub bitfield: u8,

    /// Handle to a mutex for synchronization.
    pub mutant: Handle,

    /// Pointer to the base address of the process image.
    pub image_base_address: *mut (),

    /// Pointer to the process loader data.
    pub ldr: *mut PebLoaderData,

    /// Pointer to the process parameters.
    pub process_parameters: *mut RtlUserProcessParameters,

    /// Reserved.
    pub subsystem_data: *mut (),

    /// Pointer to the process default heap.
    pub process_heap: *mut (),

    /// Pointer to a critical section used to synchronize access to the PEB.
    pub fast_peb_lock: *mut RtlCriticalSection,

    /// Pointer to a singly linked list used by the Active Template Library (ATL).
    pub atl_thunk_slist_ptr: *mut SingleListHeader,

    /// Handle to the Image File Execution Options key.
    pub ifeo_key: Handle,

    /// Cross process flags.
    pub cross_process_flags: u32,

    /// User32 kernel callback table
    pub kernel_callback_table: *mut (),

    /// Reserved.
    pub system_reserved: u32,

    /// Pointer to the Active Template Library (ATL) singly linked list (32-bit)
    pub atl_thunk_slist_ptr32: u32,

    /// Pointer to the API Set Schema.
    pub api_set_map: *mut ApiSetNamespace,

    /// Counter for TLS expansion.
    pub tls_expansion_counter: u32,

    /// Pointer to the TLS bitmap.
    pub tls_bitmap: *mut RtlBitmap,

    /// Bits for the TLS bitmap.
    pub tls_bitmap_bits: [u32; 2],

    /// Reserved for CSRSS.
    pub read_only_shared_memory_base: *mut (),

    /// Pointer to the USER_SHARED_DATA for the current SILO.
    pub shared_data: *mut (),

    /// Reserved for CSRSS.
    pub read_only_static_server_data: *mut *mut (),

    /// Pointer to the ANSI code page data.
    pub ansi_code_page_data: *mut (),

    /// Pointer to the OEM code page data.
    pub oem_code_page_data: *mut (),

    /// Pointer to the Unicode case table data.
    pub unicode_case_table_data: *mut (),

    /// The total number of system processors.
    pub number_of_processors: u32,

    /// Global flags for the system.
    pub nt_global_flag: u32,

    /// Timeout for critical sections.
    pub critical_section_timeout: i64,

    /// Reserved size for heap segments.
    pub heap_segment_reserve: usize,

    /// Committed size for heap segments.
    pub heap_segment_commit: usize,

    /// Threshold for decommitting total free heap.
    pub heap_de_commit_total_free_threshold: usize,

    /// Threshold for decommitting free heap blocks.
    pub heap_de_commit_free_block_threshold: usize,

    /// Number of process heaps.
    pub number_of_heaps: u32,

    /// Maximum number of process heaps.
    pub maximum_number_of_heaps: u32,

    /// Pointer to an array of process heaps. `process_heaps` is initialized
    /// to point to the first free byte after the PEB and `maximum_number_of_heaps`
    /// is computed from the page size used to hold the PEB, less the fixed
    /// size of this data structure.
    pub process_heaps: *mut *mut (),

    /// Pointer to the system GDI shared handle table.
    pub gdi_shared_handle_table: *mut (),

    /// Pointer to the process starter helper.
    pub process_starter_helper: *mut (),

    /// The maximum number of GDI function calls during batch operations (GdiSetBatchLimit)
    pub gdi_dcattribute_list: u32,

    /// Pointer to the loader lock critical section.
    pub loader_lock: *mut RtlCriticalSection,

    /// Major version of the operating system.
    pub os_major_version: u32,

    /// Minor version of the operating system.
    pub os_minor_version: u32,

    /// Build number of the operating system.
    pub os_build_number: u16,

    /// CSD version of the operating system.
    pub os_csd_version: u16,

    /// Platform ID of the operating system.
    pub os_platform_id: u32,

    /// Subsystem version of the current process image (PE Headers).
    pub image_subsystem: u32,

    /// Major version of the current process image subsystem (PE Headers).
    pub image_subsystem_major_version: u32,

    /// Minor version of the current process image subsystem (PE Headers).
    pub image_subsystem_minor_version: u32,

    /// Affinity mask for the current process.
    pub active_process_affinity_mask: usize,

    /// Temporary buffer for GDI handles accumulated in the current batch.
    pub gdi_handle_buffer: [u32; 60],

    /// Pointer to the post-process initialization routine available for use by the application.
    pub post_process_init_routine: Option<PostProcessInitRoutine>,

    /// Pointer to the TLS expansion bitmap.
    pub tls_expansion_bitmap: *mut RtlBitmap,

    /// Bits for the TLS expansion bitmap.
    pub tls_expansion_bitmap_bits: [u32; 32],

    /// Session ID of the current process.
    pub session_id: u32,

    /// Application compatibility flags (KACF_*).
    pub app_compat_flags: u64,

    /// Application compatibility flags user (KACF_*).
    pub app_compat_flags_user: u64,

    /// Pointer to the Application SwitchBack Compatibility Engine.
    pub shim_data: *mut (),

    /// Pointer to the Application Compatibility Engine.
    pub app_compat_info: *mut (),

    /// CSD version string of the operating system.
    pub csd_version: UnicodeString,

    /// Pointer to the process activation context.
    pub activation_context_data: *mut ActivationContextData,

    /// Pointer to the process assembly storage map.
    pub process_assembly_storage_map: *mut AssemblyStorageMap,

    /// Pointer to the system default activation context.
    pub system_default_activation_context_data: *mut ActivationContextData,

    /// Pointer to the system assembly storage map.
    pub system_assembly_storage_map: *mut AssemblyStorageMap,

    /// Minimum stack commit size.
    pub minimum_stack_commit: usize,

    /// Since 19H1 (previously FlsCallback to FlsHighIndex).
    pub spare_pointers: [*mut (); 2],

    /// Pointer to the patch loader data.
    pub patch_loader_data: *mut (),

    /// Pointer to the CHPE V2 process information (CHPEV2_PROCESS_INFO).
    pub chpe_v2_process_info: *mut (),

    /// Packaged process feature state.
    pub app_model_feature_state: u32,

    /// Spare ulongs (`u32`'s).
    pub spare_ulongs: [u32; 2],

    /// Active code page.
    pub active_code_page: u16,

    /// OEM code page.
    pub oem_code_page: u16,

    /// Code page case mapping.
    pub use_case_mapping: u16,

    /// Unused NLS field.
    pub unused_nls_field: u16,

    /// Pointer to the application WER registration data.
    pub wer_registration_data: *mut (),

    /// Pointer to the application WER assert pointer.
    pub wer_ship_assert_ptr: *mut (),

    /// Pointer to the EC bitmap on ARM64 / switchback compatibility engine (Win7 and below).
    pub ec_code_bitmap: *mut (),

    /// Reserved.
    pub image_header_hash: *mut (),

    /// ETW tracing flags.
    pub tracing_flags: u32,

    /// Reserved for CSRSS.
    pub csr_server_read_only_shared_memory_base: u64,

    /// Pointer to the thread pool worker list lock.
    pub tpp_workerp_list_lock: *mut RtlCriticalSection,

    /// Pointer to the thread pool worker list.
    pub tpp_workerp_list: ListEntry,

    /// Wait on address hash table (`RtlWaitOnAddress`).
    pub wait_on_address_hash_table: [*mut (); 128],

    /// Pointer to the telemetry coverage header. Since RS3.
    pub telemetry_coverage_header: *mut (),

    /// Cloud file flags (ProjFs and Cloud Files). Since RS4.
    pub cloud_file_flags: u32,

    /// Cloud file diagnostic flags.
    pub cloud_file_diag_flags: u32,

    /// Placeholder compatibility mode (ProjFs and Cloud Files).
    pub placeholder_compatibility_mode: i8,

    /// Reserved for placeholder compatibility mode.
    pub placeholder_compatibility_mode_reserved: [i8; 7],

    /// Pointer to leap second data. Since RS5.
    pub leap_second_data: *mut (),

    /// Leap second flags.
    pub leap_second_flags: u32,

    /// Global flags for the process.
    pub nt_global_flag2: u32,

    /// Extended feature disable mask (AVX). Since Win11.
    pub extended_feature_disable_mask: u64,
}

pub type PostProcessInitRoutine = unsafe extern "system" fn();

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub union SingleListHeader {
    pub alignment: u64,
    pub region: u64,
    pub _padding: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlBitmap {
    pub size: u32,
    pub buffer: *mut u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ApiSetNamespace {
    pub version: u32,
    pub size: u32,
    pub flags: u32,
    pub count: u32,
    pub entry_offset: u32,
    pub hash_offset: u32,
    pub hash_factor: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlCriticalSection {
    pub synchronization: RtlCriticalSectionSynchronization,
    pub lock_count: i32,
    pub recursion_count: i32,
    pub owning_thread: *mut (),
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union RtlCriticalSectionSynchronization {
    pub event: RtlCriticalSectionSynchronizationEvent,
    pub raw_event: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RtlCriticalSectionSynchronizationEvent {
    pub r#type: u8,
    pub absolute: u8,
    pub size: u8,
    pub inserted: u8,
    pub signal_state: i32,
    pub wait_list_head: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlUserProcessParameters {
    pub max_length: u32,
    pub length: u32,

    pub flags: u32,
    pub debug_flags: u32,

    pub console_handle: Handle,
    pub console_flags: u32,
    pub standard_input: Handle,
    pub standard_output: Handle,
    pub standard_error: Handle,

    pub current_directory: CurrentDirectory,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    pub environment: *mut (),

    pub starting_x: u32,
    pub starting_y: u32,
    pub count_x: u32,
    pub count_y: u32,
    pub count_chars_x: u32,
    pub count_chars_y: u32,
    pub fill_attribute: u32,

    pub window_flags: u32,
    pub show_window_flags: u32,
    pub window_title: UnicodeString,
    pub desktop_info: UnicodeString,
    pub shell_info: UnicodeString,
    pub runtime_data: UnicodeString,
    pub current_directories: [DriveLetterCurrentDirectory; 32],

    pub environment_size: usize,
    pub environment_version: usize,

    pub package_dependency_data: *mut (),
    pub process_group_id: u32,
    pub loader_threads: u32,
    pub redirection_dll_name: UnicodeString,
    pub heap_partition_name: UnicodeString,
    pub default_threadpool_cpu_set_masks: *mut u64,
    pub default_threadpool_cpu_set_mask_count: u32,
    pub default_threadpool_thread_max: u32,
    pub heap_memory_type_mask: u32, // win11 22h2
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CurrentDirectory {
    pub dos_path: UnicodeString,
    pub handle: Handle,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DriveLetterCurrentDirectory {
    pub flags: u16,
    pub length: u16,
    pub timestamp: u32,
    pub dos_path: AnsiString,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnsiString {
    pub length: u16,
    pub max_length: u16,
    pub buffer: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExceptionRegistrationRecord {
    pub next: *mut ExceptionRegistrationRecord,
    pub handler: *mut (),
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union TibData {
    pub fiber_data: *mut (),
    pub version: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadInfoBlock {
    // NT_TIB
    pub exception_list: *mut ExceptionRegistrationRecord,
    pub stack_base: *mut (),
    pub stack_limit: *mut (),
    pub sub_system_tib: *mut (),
    pub data: TibData,
    pub arbitrary_user_pointer: *mut (),
    pub self_ptr: *mut ThreadEnvBlock,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadEnvBlock {
    /// Thread Information Block (TIB) contains the thread's stack,
    /// base and limit addresses, the current stack pointer, and the exception list.
    pub tib: *mut ThreadInfoBlock,

    /// Reserved.
    pub environment_pointer: *mut (),

    /// Client ID for this thread.
    pub client_id: ClientId,

    /// A handle to an active Remote Procedure Call (RPC) if the thread is currently involved in an RPC operation.
    pub active_rpc_handle: *mut (),

    /// A pointer to the __declspec(thread) local storage array.
    pub thread_local_storage_pointer: *mut (),

    /// A pointer to the Process Environment Block (PEB).
    pub process_environment_block: *mut ProcessEnvBlock,

    /// The previous Win32 error value for this thread.
    pub last_error_value: u32,

    /// The number of critical sections currently owned by this thread.
    pub count_of_owned_critical_sections: u32,

    /// Reserved.
    pub csr_client_thread: *mut (),

    /// Reserved for win32k.sys.
    pub win32_thread_info: *mut (),

    /// Reserved for user32.dll.
    pub user32_reserved: [u32; 26],

    /// Reserved for winsrv.dll.
    pub user_reserved: [u32; 5],

    /// Reserved.
    pub wow32_reserved: *mut (),

    /// The LCID of the current thread.
    pub current_locale: u32,

    /// Reserved.
    pub fp_software_status_register: u32,

    /// Reserved.
    pub reserved_for_debugger_instrumentation: [*mut (); 16],

    /// Reserved.
    pub system_reserved1: [*mut (); 25],

    /// Per-thread fiber local storage.
    pub heap_fls_data: *mut (),

    /// Reserved.
    pub rng_state: [usize; 4],

    /// Placeholder compatibility mode (ProjFs and Cloud Files).
    pub placeholder_compatibility_mode: i8,

    /// Indicates whether placeholder hydration is always explicit.
    pub placeholder_hydration_always_explicit: u8,

    /// ProjFs and Cloud Files (reparse point) file virtualization.
    pub placeholder_reserved: [i8; 10],

    /// The process ID (PID) that the current COM server thread is acting on behalf of.
    pub proxied_process_id: u32,

    /// Pointer to the activation context stack for the current thread.
    pub activation_stack: ActivationContextStack,

    /// Opaque operation on behalf of another user or process.
    pub working_on_behalf_ticket: [u8; 8],

    /// The last exception status for the current thread.
    pub exception_code: NtStatus,

    /// Pointer to the activation context stack for the current thread.
    pub activation_context_stack_pointer: *mut ActivationContextStack,

    /// The stack pointer (SP) of the current system call or exception during instrumentation.
    pub instrumentation_callback_sp: usize,

    /// The program counter (PC) of the previous system call or exception during instrumentation.
    pub instrumentation_callback_previous_pc: usize,

    /// The stack pointer (SP) of the previous system call or exception during instrumentation.
    pub instrumentation_callback_previous_sp: usize,

    /// The miniversion ID of the current transacted file operation.
    pub tx_fs_context: u32,

    /// Indicates the state of the system call or exception instrumentation callback.
    pub instrumentation_callback_disabled: u8,

    /// Indicates the state of alignment exceptions for unaligned load/store operations.
    pub unaligned_load_store_exceptions: u8,

    /// Reserved for GDI (Win32k).
    pub gdi_teb_batch: GdiTebBatch,

    /// Real client ID.
    pub real_client_id: ClientId,

    /// GDI cached process handle.
    pub gdi_cached_process_handle: Handle,

    /// GDI client PID.
    pub gdi_client_pid: u32,

    /// GDI client TID.
    pub gdi_client_tid: u32,

    /// GDI thread local info.
    pub gdi_thread_local_info: *mut (),

    /// User32 (Win32k) thread information.
    pub win32_client_info: [usize; 62],

    /// Reserved for opengl32.dll.
    pub gl_dispatch_table: [*mut (); 233],

    /// Reserved.
    pub gl_reserved1: [usize; 29],

    /// Reserved.
    pub gl_reserved2: *mut (),

    /// Reserved.
    pub gl_section_info: *mut (),

    /// Reserved.
    pub gl_section: *mut (),

    /// Reserved.
    pub gl_table: *mut (),

    /// Reserved.
    pub gl_current_rc: *mut (),

    /// Reserved.
    pub gl_context: *mut (),

    /// The previous status value for this thread.
    pub last_status_value: NtStatus,

    /// A static string for use by the application.
    pub static_unicode_string: UnicodeString,

    /// A static buffer for use by the application.
    pub static_unicode_buffer: [u16; 261],

    /// The maximum stack size and indicates the base of the stack.
    pub deallocation_stack: *mut (),

    /// Data for Thread Local Storage.
    pub tls_slots: [*mut (); 64],

    /// Reserved for TLS.
    pub tls_links: ListEntry,

    /// Reserved for NTVDM.
    pub vdm: *mut (),

    /// Reserved for RPC. The pointer is XOR'd with RPC_THREAD_POINTER_KEY.
    pub reserved_for_nt_rpc: *mut (),

    /// Reserved for Debugging (DebugActiveProcess).
    pub dbg_ss_reserved: [*mut (); 2],

    /// The error mode for the current thread.
    pub hard_error_mode: u32,

    /// Reserved.
    pub instrumentation: [*mut (); 11],

    /// Reserved.
    pub activity_id: Guid,

    /// The identifier of the service that created the thread.
    pub sub_process_tag: *mut (),

    /// Reserved.
    pub perflib_data: *mut (),

    /// Reserved.
    pub etw_trace_data: *mut (),

    /// The address of a socket handle during a blocking socket operation.
    pub win_sock_data: Handle,

    /// The number of function calls accumulated in the current GDI batch.
    pub gdi_batch_count: u32,

    /// The preferred processor for the current thread.
    pub ideal_processor_value: u32,

    /// The minimum size of the stack available during any stack overflow exceptions.
    pub guaranteed_stack_bytes: u32,

    /// Reserved.
    pub reserved_for_perf: *mut (),

    /// Reserved for Object Linking and Embedding (OLE).
    pub reserved_for_ole: *mut (),

    /// Indicates whether the thread is waiting on the loader lock.
    pub waiting_on_loader_lock: u32,

    /// The saved priority state for the thread.
    pub saved_priority_state: *mut (),

    /// Reserved.
    pub reserved_for_code_coverage: usize,

    /// Reserved.
    pub thread_pool_data: *mut (),

    /// Pointer to the TLS expansion slots for the thread.
    pub tls_expansion_slots: *mut *mut (),

    /// CHPE V2 CPU area info.
    pub chpe_v2_cpu_area_info: *mut (),

    /// Unused.
    pub unused: *mut (),

    /// The generation of the MUI data.
    pub mui_generation: u32,

    /// Indicates whether the thread is impersonating another security context.
    pub is_impersonating: u32,

    /// Pointer to the NLS cache.
    pub nls_cache: *mut (),

    /// Pointer to the AppCompat/Shim Engine data.
    pub shim_data: *mut (),

    /// Reserved.
    pub heap_data: u32,

    /// Handle to the current transaction associated with the thread.
    pub current_transaction_handle: Handle,

    /// Pointer to the active frame for the thread.
    pub active_frame: *mut TebActiveFrame,

    /// Reserved for FLS.
    pub fls_data: *mut (),

    /// Pointer to the preferred languages for the current thread.
    pub preferred_languages: *mut (),

    /// Pointer to the user-preferred languages for the current thread.
    pub user_pref_languages: *mut (),

    /// Pointer to the merged preferred languages for the current thread.
    pub merged_pref_languages: *mut (),

    /// Indicates whether the thread is impersonating another user's language settings.
    pub mui_impersonation: u32,

    /// Reserved.
    pub cross_teb_flags: u16,

    /// Modifies the state and behavior of the current thread.
    pub same_teb_flags: u16,

    /// Pointer to the callback function called when a KTM transaction scope is entered.
    pub txn_scope_enter_callback: *mut (),

    /// Pointer to the callback function called when a KTM transaction scope is exited.
    pub txn_scope_exit_callback: *mut (),

    /// Pointer to optional context data for KTM transaction scope callbacks.
    pub txn_scope_context: *mut (),

    /// The lock count of critical sections for the current thread.
    pub lock_count: u32,

    /// The offset to the WOW64 TEB for the current thread.
    pub wow_teb_offset: i32,

    /// Pointer to the DLL containing the resource.
    pub resource_ret_value: *mut (),

    /// Reserved for Windows Driver Framework (WDF).
    pub reserved_for_wdf: *mut (),

    /// Reserved for the Microsoft C runtime (CRT).
    pub reserved_for_crt: u64,

    /// The Host Compute Service (HCS) container identifier.
    pub effective_container_id: Guid,

    /// Reserved for Kernel32!Sleep (SpinWait). Since Win11.
    pub last_sleep_counter: u64,

    /// Reserved for Kernel32!Sleep (SpinWait).
    pub spin_call_count: u32,

    /// Extended feature disable mask (AVX).
    pub extended_feature_disable_mask: u64,

    /// Reserved. Since 24H2.
    pub scheduler_shared_data_slot: *mut (),

    /// Reserved.
    pub heap_walk_context: *mut (),

    /// The primary processor group affinity of the thread.
    pub primary_group_affinity: GroupAffinity,

    /// Read-copy-update (RCU) synchronization context.
    pub rcu: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GroupAffinity {
    pub mask: usize,
    pub group: u16,
    pub reserved: [u16; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TebActiveFrame {
    pub flags: u32,
    pub prev: *mut TebActiveFrame,
    pub context: *mut RtlActiveFrameContext,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlActiveFrameContext {
    pub flags: u32,
    pub frame_name: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct GdiTebBatch {
    pub offset: u32,
    pub hdc: usize,
    pub buffer: [u32; 310],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivationContextStack {
    pub active_frame: *mut RtlActivationContextStackFrame,
    pub frame_list_cache: ListEntry,
    pub flags: u32,
    pub next_cookie_sequence_number: u32,
    pub stack_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlActivationContextStackFrame {
    pub prev: *mut RtlActivationContextStackFrame,
    pub activation_context: *mut ActivationContext,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivationContext {
    pub ref_count: i32,
    pub flags: u32,
    pub activation_context_data: *mut ActivationContextData,
    pub notification_routine: Option<ActivationContextNotifyRoutine>,
    pub notification_context: *mut (),
    pub sent_notifications: [u32; 8],
    pub disabled_notifications: [u32; 8],
    pub storage_map: AssemblyStorageMap,
    pub inline_storage_map_entries: [*mut AssemblyStorageMapEntry; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ActivationContextData {
    pub magic: u32,
    pub header_size: u32,
    pub format_version: u32,
    pub total_size: u32,
    pub default_toc_offset: u32,
    pub extended_toc_offset: u32,
    pub assembly_roster_offset: u32,
    pub flags: u32,
}

pub type ActivationContextNotifyRoutine = unsafe extern "system" fn(
    notification_type: u32,
    activation_context: *mut ActivationContext,
    activation_context_data: *mut ActivationContextData,
    notification_context: *mut (),
    notification_data: *mut (),
    disable_this_notification: *mut bool,
);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AssemblyStorageMap {
    pub flags: u32,
    pub assembly_count: u32,
    pub assembly_array: *mut *mut AssemblyStorageMapEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AssemblyStorageMapEntry {
    pub flags: u32,
    pub dos_path: UnicodeString,
    pub handle: *mut (),
}

#[repr(C)]
#[derive(Clone, Copy)]
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
    pub start_address: *mut (),
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
    pub object_name: *mut UnicodeString,
    pub attributes: u32,
    pub security_descriptor: *mut (),
    pub security_quality_of_service: *mut (),
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ThreadBasicInformation {
    pub exit_status: NtStatus,
    pub teb_base_address: *mut ThreadEnvBlock,
    pub client_id: ClientId,
    pub affinity_mask: usize,
    pub priority: i32,
    pub base_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessBasicInformation {
    pub exit_status: NtStatus,
    pub peb_base_address: *mut ProcessEnvBlock,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub pid: usize,
    pub inherited_from_pid: usize,
}

#[repr(C)]
pub struct MemoryBasicInformation {
    pub base_address: *mut (),
    pub allocation_base: *mut (),
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
    pub section: *mut (),
    pub mapped_base: *mut (),
    pub image_base: *mut (),
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
    pub callback: *mut (),
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
pub struct RtlVectoredHandlerList {
    pub veh_lock: *mut SRWLock,
    pub veh_list: ListEntry,

    pub vch_lock: *mut SRWLock,
    pub vch_list: ListEntry,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtlVectoredHandlerEntry {
    pub list: ListEntry,
    pub ref_count: *mut u64,
    pub zero: u32,
    pub padding: u32,
    pub encoded_handler: *mut (),
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
    pub exception_address: *mut (),
    pub number_parameters: u32,
    pub exception_information: [usize; 15],
}

#[repr(C)]
pub struct ApcCallbackDataContext {
    pub parameter: *mut (),
    pub context_record: *mut ThreadContext,
    pub reserved_0: *mut (),
    pub reserved_1: *mut (),
}
