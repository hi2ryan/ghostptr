use bitflags::bitflags;

bitflags! {
    /// Represents process access rights.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ProcessAccess: u32 {
        const TERMINATE                	= 0x0001;
        const CREATE_THREAD            	= 0x0002;
        const VM_OPERATION             	= 0x0008;
        const VM_READ                  	= 0x0010;
        const VM_WRITE                 	= 0x0020;
        const DUP_HANDLE               	= 0x0040;
        const CREATE_PROCESS           	= 0x0080;
        const SET_QUOTA                	= 0x0100;
        const SET_INFORMATION          	= 0x0200;
        const QUERY_INFORMATION        	= 0x0400;
        const SUSPEND_RESUME           	= 0x0800;
        const QUERY_LIMITED_INFORMATION	= 0x1000;
        const SET_LIMITED_INFORMATION  	= 0x2000;
        const SYNCHRONIZE              	= 0x00100000;
        const ALL_ACCESS               	= 0x001F_FFFF;
    }

    /// Represents memory protection.
    /// These values determine how interactions with the memory are allowed to proceed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryProtection: u32 {
        /// Disables all access to the committed region of pages.
        const NOACCESS               = 0x01;

        /// Enables execute access only.
        const EXECUTE                = 0x10;

        /// Enables read-only or execute-read access.
        const READONLY               = 0x02;

        /// Enables read-write or execute-read-write access.
        const READWRITE              = 0x04;

        /// Enables copy-on-write access.
        const WRITECOPY              = 0x08;

        /// Enables execute-read access.
        const EXECUTE_READ           = 0x20;

        /// Enables execute-read-write access.
        const EXECUTE_READWRITE      = 0x40;

        /// Enables execute-copy-on-write access.
        const EXECUTE_WRITECOPY      = 0x80;

        /// Marks the region as a guard page.
        const GUARD                  = 0x100;

        /// Disables caching of the committed pages.
        const NOCACHE                = 0x200;

        /// Enables write-combined memory.
        const WRITECOMBINE           = 0x400;

        /// Pages in this region cannot be the target of Control Flow Guard.
        const TARGETS_INVALID        = 0x40000000;

        /// Pages in this region cannot have their CFG targets updated.
        const TARGETS_NO_UPDATE      = 0x40000000;
    }

    /// Represents memory state flags.
    /// These values indicate whether a region of pages is committed, reserved, or free.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryState: u32 {
        /// Indicates committed pages for which physical storage has been allocated.
        const COMMIT  = 0x1000;

        /// Indicates reserved pages where virtual memory is set aside but not committed.
        const RESERVE = 0x2000;

        /// Indicates free pages not currently allocated or reserved.
        const FREE    = 0x10000;
    }

    /// Represents memory type flags.
    /// These values describe how the memory was allocated.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct MemoryType: u32 {
        /// Indicates that the memory pages are mapped into the view of an image section.
        const IMAGE   = 0x1000000;

        /// Indicates that the memory pages are mapped into the view of a section.
        const MAPPED  = 0x40000;

        /// Indicates that the memory pages are private (not shared).
        const PRIVATE = 0x20000;
    }

    /// Represents memory allocation type flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AllocationType: u32 {
        /// Allocates memory charges (commit) from the paging file.
        const COMMIT = 0x00001000;

        /// Reserves a range of the process's virtual address space without allocating physical storage.
        const RESERVE = 0x00002000;

        /// Indicates that the memory region is reset to zero and decommitted.
        const RESET = 0x00080000;

        /// Reserves an address range without allocating physical storage or page tables.
        const LARGE_PAGES = 0x20000000;

        /// Allocates memory at the highest possible address.
        const TOP_DOWN = 0x00100000;

        /// Reserves memory using the memory-mapped file section.
        const PHYSICAL = 0x00400000;

        /// Enables write tracking for the allocated memory (used with AWE).
        const WRITE_WATCH = 0x00200000;

        /// Indicates that the memory is intended for executable code and should be protected accordingly.
        const MEM_COALESCE_PLACEHOLDERS = 0x00000001;

        /// Indicates that the memory region is a placeholder.
        const MEM_RESERVE_PLACEHOLDER = 0x00040000;

        /// Indicates that the memory region is being replaced with a placeholder.
        const MEM_REPLACE_PLACEHOLDER = 0x00004000;

        /// Indicates that the memory region is being reset and reused.
        const RESET_UNDO = 0x1000000;
    }

    /// Represents free operation type flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FreeType: u32 {
        const DECOMMIT = 0x00004000;
        const RELEASE  = 0x00008000;
    }

    /// Represents thread access rights.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ThreadAccess: u32 {
        const TERMINATE                     = 0x0001;
        const SUSPEND_RESUME                = 0x0002;
        const GET_CONTEXT                   = 0x0008;
        const SET_CONTEXT                   = 0x0010;
        const SET_INFORMATION               = 0x0020;
        const QUERY_INFORMATION             = 0x0040;
        const SET_THREAD_TOKEN              = 0x0080;
        const IMPERSONATE                   = 0x0100;
        const DIRECT_IMPERSONATION          = 0x0200;
        const SET_LIMITED_INFORMATION       = 0x0400;
        const QUERY_LIMITED_INFORMATION     = 0x0800;
        const SYNCHRONIZE                   = 0x0010_0000;
        const ALL_ACCESS                    = 0x1FFFFF;
    }

    /// Flags controlling which parts of a thread CONTEXT are read or written.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ThreadContextFlags: u32 {
        /// Indicates that this is an AMD64 (x86‑64) ThreadContext structure.
        const AMD64 = 0x0010_0000;

        /// Control registers: RIP, RSP, RBP, segment selectors, and EFlags.
        const CONTROL = 0x0010_0001;

        /// Integer registers: RAX, RBX, RCX, RDX, RSI, RDI, R8–R15.
        const INTEGER = 0x0010_0002;

        /// Segment registers: CS, DS, ES, FS, GS, SS.
        const SEGMENTS = 0x0010_0004;

        /// Floating‑point and SSE state (XMM registers, MXCSR).
        const FLOATING_POINT = 0x0010_0008;

        /// Hardware debug registers: DR0–DR7.
        const DEBUG_REGISTERS = 0x0010_0010;

        /// Extended processor state (AVX, AVX‑512, etc.) via XSAVE.
        const XSTATE = 0x0010_0040;

		/// The typical set used for unwinding and exception handling.
        ///
        /// CONTROL | INTEGER | FLOATING_POINT
        const FULL = 0x0010_0001 | 0x0010_0002 | 0x0010_0008;

		/// The complete AMD64 context.
		/// 
		/// CONTROL | INTEGER | SEGMENTS | FLOATING_POINT | DEBUG_REGISTERS
        const ALL = 0x0010_0001 | 0x0010_0002 | 0x0010_0004 | 0x0010_0008 | 0x0010_0010;

		/// Indicates the thread is actively handling an exception.
		const EXCEPTION_ACTIVE = 0x0800_0000;

		/// Indicates the thread is servicing a system call.
		const SERVICE_ACTIVE = 0x1000_0000;

		/// Indicates the thread has been unwound to a call site.
		const UNWOUND_TO_CALL = 0x2000_0000;

		/// Request that the kernel capture extended exception state.
		const EXCEPTION_REQUEST = 0x4000_0000;

		/// Request that the kernel include exception reporting information.
		const EXCEPTION_REPORTING = 0x8000_0000;

		/// Indicates the thread is being debugged by a kernel debugger.
		const KERNEL_DEBUGGER = 0x0400_0000;

		/// Control‑flow enforcement technology (CET) kernel state.
		const KERNEL_CET = 0x0010_1000;
    }

	/// Flags controlling how a thread acts upon creation.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
	pub struct ThreadCreateFlags: u32 {
		const NONE = 0;
		const CREATE_SUSPENDED = 0x4;
	}
}
