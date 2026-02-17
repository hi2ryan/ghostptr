macro_rules! impl_bitflags {
    ($ty:ident) => {
        impl $ty {
            #[inline(always)]
            pub const fn bits(self) -> u32 {
                self.0
            }

            #[inline(always)]
            pub const fn from_bits(bits: u32) -> Self {
                Self(bits)
            }

            #[inline(always)]
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            #[inline(always)]
            pub const fn intersects(self, other: Self) -> bool {
                (self.0 & other.0) != 0
            }

            #[inline(always)]
            pub fn insert(&mut self, other: Self) {
                self.0 |= other.0;
            }

            #[inline(always)]
            pub fn remove(&mut self, other: Self) {
                self.0 &= !other.0;
            }

            #[inline(always)]
            pub fn toggle(&mut self, other: Self) {
                self.0 ^= other.0;
            }

            #[inline(always)]
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }
        }

        impl core::fmt::Debug for $ty {
            fn fmt(
                &self,
                f: &mut core::fmt::Formatter<'_>,
            ) -> core::fmt::Result {
                write!(f, "{}(0x{:X})", stringify!($ty), self.0)
            }
        }

        impl core::ops::BitOr for $ty {
            type Output = Self;

            #[inline(always)]
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $ty {
            #[inline(always)]
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl core::ops::BitAnd for $ty {
            type Output = Self;

            #[inline(always)]
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $ty {
            #[inline(always)]
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl core::ops::BitXor for $ty {
            type Output = Self;

            #[inline(always)]
            fn bitxor(self, rhs: Self) -> Self {
                Self(self.0 ^ rhs.0)
            }
        }

        impl core::ops::BitXorAssign for $ty {
            #[inline(always)]
            fn bitxor_assign(&mut self, rhs: Self) {
                self.0 ^= rhs.0;
            }
        }

        impl core::ops::Not for $ty {
            type Output = Self;

            #[inline(always)]
            fn not(self) -> Self {
                Self(!self.0)
            }
        }

        impl From<u32> for $ty {
            #[inline(always)]
            fn from(bits: u32) -> Self {
                Self(bits)
            }
        }

        impl From<$ty> for u32 {
            #[inline(always)]
            fn from(flags: $ty) -> u32 {
                flags.0
            }
        }
    };
}

/// Represents process access rights.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessAccess(u32);

impl ProcessAccess {
    pub const TERMINATE: Self = Self(0x0001);
    pub const CREATE_THREAD: Self = Self(0x0002);
    pub const VM_OPERATION: Self = Self(0x0008);
    pub const VM_READ: Self = Self(0x0010);
    pub const VM_WRITE: Self = Self(0x0020);
    pub const DUP_HANDLE: Self = Self(0x0040);
    pub const CREATE_PROCESS: Self = Self(0x0080);
    pub const SET_QUOTA: Self = Self(0x0100);
    pub const SET_INFORMATION: Self = Self(0x0200);
    pub const QUERY_INFORMATION: Self = Self(0x0400);
    pub const SUSPEND_RESUME: Self = Self(0x0800);
    pub const QUERY_LIMITED_INFORMATION: Self = Self(0x1000);
    pub const SET_LIMITED_INFORMATION: Self = Self(0x2000);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);
    pub const ALL: Self = Self(0x001F_FFFF);
}

impl_bitflags!(ProcessAccess);

/// Represents memory protection.
/// These values determine how interactions with the memory are allowed to proceed.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryProtection(u32);

impl MemoryProtection {
    /// Disables all access to the committed region of pages.
    pub const NOACCESS: Self = Self(0x01);

    /// Enables execute access only.
    pub const EXECUTE: Self = Self(0x10);

    /// Enables read-only or execute-read access.
    pub const READONLY: Self = Self(0x02);

    /// Enables read-write or execute-read-write access.
    pub const READWRITE: Self = Self(0x04);

    /// Enables copy-on-write access.
    pub const WRITECOPY: Self = Self(0x08);

    /// Enables execute-read access.
    pub const EXECUTE_READ: Self = Self(0x20);

    /// Enables execute-read-write access.
    pub const EXECUTE_READWRITE: Self = Self(0x40);

    /// Enables execute-copy-on-write access.
    pub const EXECUTE_WRITECOPY: Self = Self(0x80);

    /// Marks the region as a guard page.
    pub const GUARD: Self = Self(0x100);

    /// Disables caching of the committed pages.
    pub const NOCACHE: Self = Self(0x200);

    /// Enables write-combined memory.
    pub const WRITECOMBINE: Self = Self(0x400);

    /// Pages in this region cannot be the target of Control Flow Guard.
    pub const TARGETS_INVALID: Self = Self(0x4000_0000);

    /// Pages in this region cannot have their CFG targets updated.
    pub const TARGETS_NO_UPDATE: Self = Self(0x4000_0000);
}

impl MemoryProtection {
    /// Returns `true` if the memory region is marked as a guard page.
    #[inline]
    pub fn is_guarded(self) -> bool {
        self.contains(Self::GUARD)
    }

    /// Returns `true` if the memory region is executable.
    #[inline]
    pub fn is_executable(self) -> bool {
        self.intersects(
            Self::EXECUTE
                | Self::EXECUTE_READ
                | Self::EXECUTE_READWRITE
                | Self::EXECUTE_WRITECOPY,
        )
    }

    /// Returns `true` if the memory region is readable.
    #[inline]
    pub fn is_readable(self) -> bool {
        self.intersects(
            Self::READONLY
                | Self::READWRITE
                | Self::WRITECOPY
                | Self::EXECUTE_READ
                | Self::EXECUTE_READWRITE
                | Self::EXECUTE_WRITECOPY,
        )
    }

    /// Returns `true` if the memory region is writable.
    #[inline]
    pub fn is_writable(self) -> bool {
        self.intersects(
            Self::READWRITE
                | Self::WRITECOPY
                | Self::EXECUTE_READWRITE
                | Self::EXECUTE_WRITECOPY,
        )
    }
}

impl core::fmt::Display for MemoryProtection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let r = if self.is_readable() { 'r' } else { '-' };
        let w = if self.is_writable() { 'w' } else { '-' };
        let x = if self.is_executable() { 'x' } else { '-' };
        let g = if self.is_guarded() { 'G' } else { '-' };

        write!(f, "MemoryProtection({}{}{}{})", r, w, x, g)
    }
}

impl_bitflags!(MemoryProtection);

/// Represents memory state flags.
/// These values indicate whether a region of pages is committed, reserved, or free.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryState(u32);

impl MemoryState {
    /// Indicates committed pages for which physical storage has been allocated.
    pub const COMMIT: Self = Self(0x1000);

    /// Indicates reserved pages where virtual memory is set aside but not committed.
    pub const RESERVE: Self = Self(0x2000);

    /// Indicates free pages not currently allocated or reserved.
    pub const FREE: Self = Self(0x10000);
}

impl_bitflags!(MemoryState);

/// Represents memory type flags.
/// These values describe how the memory was allocated.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryType(u32);

impl MemoryType {
    /// Indicates that the memory pages are mapped into the view of an image section.
    pub const IMAGE: Self = Self(0x1000000);

    /// Indicates that the memory pages are mapped into the view of a section.
    pub const MAPPED: Self = Self(0x40000);

    /// Indicates that the memory pages are private (not shared).
    pub const PRIVATE: Self = Self(0x20000);
}

impl_bitflags!(MemoryType);

/// Represents memory allocation type flags.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AllocationType(u32);

impl AllocationType {
    /// Allocates memory charges (commit) from the paging file.
    pub const COMMIT: Self = Self(0x00001000);

    /// Reserves a range of the process's virtual address space without allocating physical storage.
    pub const RESERVE: Self = Self(0x00002000);

    /// Indicates that the memory region is reset to zero and decommitted.
    pub const RESET: Self = Self(0x00080000);

    /// Reserves an address range without allocating physical storage or page tables.
    pub const LARGE_PAGES: Self = Self(0x20000000);

    /// Allocates memory at the highest possible address.
    pub const TOP_DOWN: Self = Self(0x00100000);

    /// Reserves memory using the memory-mapped file section.
    pub const PHYSICAL: Self = Self(0x00400000);

    /// Enables write tracking for the allocated memory (used with AWE).
    pub const WRITE_WATCH: Self = Self(0x00200000);

    /// Indicates that the memory is intended for executable code and should be protected accordingly.
    pub const MEM_COALESCE_PLACEHOLDERS: Self = Self(0x00000001);

    /// Indicates that the memory region is a placeholder.
    pub const MEM_RESERVE_PLACEHOLDER: Self = Self(0x00040000);

    /// Indicates that the memory region is being replaced with a placeholder.
    pub const MEM_REPLACE_PLACEHOLDER: Self = Self(0x00004000);

    /// Indicates that the memory region is being reset and reused.
    pub const RESET_UNDO: Self = Self(0x1000000);
}

impl_bitflags!(AllocationType);

/// Represents free operation type flags.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FreeType(u32);

impl FreeType {
    pub const DECOMMIT: Self = Self(0x00004000);
    pub const RELEASE: Self = Self(0x00008000);
}

impl_bitflags!(FreeType);

/// Represents thread access rights.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadAccess(u32);

impl ThreadAccess {
    pub const TERMINATE: Self = Self(0x0001);
    pub const SUSPEND_RESUME: Self = Self(0x0002);
    pub const GET_CONTEXT: Self = Self(0x0008);
    pub const SET_CONTEXT: Self = Self(0x0010);
    pub const SET_INFORMATION: Self = Self(0x0020);
    pub const QUERY_INFORMATION: Self = Self(0x0040);
    pub const SET_THREAD_TOKEN: Self = Self(0x0080);
    pub const IMPERSONATE: Self = Self(0x0100);
    pub const DIRECT_IMPERSONATION: Self = Self(0x0200);
    pub const SET_LIMITED_INFORMATION: Self = Self(0x0400);
    pub const QUERY_LIMITED_INFORMATION: Self = Self(0x0800);
    pub const SYNCHRONIZE: Self = Self(0x0010_0000);
    pub const ALL: Self = Self(0x001F_FFFF);
}

impl_bitflags!(ThreadAccess);

/// Flags controlling which parts of a thread CONTEXT are read or written.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadContextFlags(u32);

impl ThreadContextFlags {
    /// Indicates that this is an AMD64 (x86-64) ThreadContext structure.
    pub const AMD64: Self = Self(0x0010_0000);

    /// Control registers: RIP, RSP, RBP, segment selectors, and EFlags.
    pub const CONTROL: Self = Self(0x0010_0001);

    /// Integer registers: RAX, RBX, RCX, RDX, RSI, RDI, R8–R15.
    pub const INTEGER: Self = Self(0x0010_0002);

    /// Segment registers: CS, DS, ES, FS, GS, SS.
    pub const SEGMENTS: Self = Self(0x0010_0004);

    /// Floating-point and SSE state (XMM registers, MXCSR).
    pub const FLOATING_POINT: Self = Self(0x0010_0008);

    /// Hardware debug registers: DR0–DR7.
    pub const DEBUG_REGISTERS: Self = Self(0x0010_0010);

    /// Extended processor state (AVX, AVX-512, etc.) via XSAVE.
    pub const XSTATE: Self = Self(0x0010_0040);

    /// The typical set used for unwinding and exception handling.
    /// CONTROL | INTEGER | FLOATING_POINT
    pub const FULL: Self = Self(0x0010_0001 | 0x0010_0002 | 0x0010_0008);

    /// The complete AMD64 context.
    /// CONTROL | INTEGER | SEGMENTS | FLOATING_POINT | DEBUG_REGISTERS
    pub const ALL: Self = Self(
        0x0010_0001
            | 0x0010_0002
            | 0x0010_0004
            | 0x0010_0008
            | 0x0010_0010,
    );

    /// Indicates the thread is actively handling an exception.
    pub const EXCEPTION_ACTIVE: Self = Self(0x0800_0000);

    /// Indicates the thread is servicing a system call.
    pub const SERVICE_ACTIVE: Self = Self(0x1000_0000);

    /// Indicates the thread has been unwound to a call site.
    pub const UNWOUND_TO_CALL: Self = Self(0x2000_0000);

    /// Request that the kernel capture extended exception state.
    pub const EXCEPTION_REQUEST: Self = Self(0x4000_0000);

    /// Request that the kernel include exception reporting information.
    pub const EXCEPTION_REPORTING: Self = Self(0x8000_0000);

    /// Indicates the thread is being debugged by a kernel debugger.
    pub const KERNEL_DEBUGGER: Self = Self(0x0400_0000);

    /// Control-flow enforcement technology (CET) kernel state.
    pub const KERNEL_CET: Self = Self(0x0010_1000);
}

impl_bitflags!(ThreadContextFlags);

/// Flags controlling how a thread acts upon creation.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThreadCreationFlags {
    None = 0x0,
    Suspended = 0x4,
}

/// Characteristics describing a PE section.
///
/// These flags control how the section is linked, aligned, and mapped
/// into memory by the Windows loader.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionCharacteristics(u32);

impl SectionCharacteristics {
    /// Reserved.
    /// Should be zero in modern binaries.
    pub const TYPE_NO_PAD: Self = Self(0x0000_0008);

    /// Section contains executable code.
    pub const CNT_CODE: Self = Self(0x0000_0020);

    /// Section contains initialized data.
    pub const CNT_INITIALIZED_DATA: Self = Self(0x0000_0040);

    /// Section contains uninitialized data (BSS).
    pub const CNT_UNINITIALIZED_DATA: Self = Self(0x0000_0080);

    /// Reserved for linker use.
    pub const LNK_OTHER: Self = Self(0x0000_0100);

    /// Section contains comments or other non-image data.
    /// This section is not mapped into memory.
    pub const LNK_INFO: Self = Self(0x0000_0200);

    /// Section is removed during linking.
    pub const LNK_REMOVE: Self = Self(0x0000_0800);

    /// Section contains COMDAT data.
    pub const LNK_COMDAT: Self = Self(0x0000_1000);

    /// Section contains data referenced through the global pointer (GP).
    pub const GPREL: Self = Self(0x0000_8000);

    /// Obsolete.
    pub const MEM_PURGEABLE: Self = Self(0x0002_0000);

    /// Obsolete.
    /// Alias of `MEM_PURGEABLE`.
    pub const MEM_16BIT: Self = Self(0x0002_0000);

    /// Obsolete.
    pub const MEM_LOCKED: Self = Self(0x0004_0000);

    /// Obsolete.
    pub const MEM_PRELOAD: Self = Self(0x0008_0000);

    /// Align section data on a 1-byte boundary.
    pub const ALIGN_1BYTES: Self = Self(0x0010_0000);

    /// Align section data on a 2-byte boundary.
    pub const ALIGN_2BYTES: Self = Self(0x0020_0000);

    /// Align section data on a 4-byte boundary.
    pub const ALIGN_4BYTES: Self = Self(0x0030_0000);

    /// Align section data on an 8-byte boundary.
    pub const ALIGN_8BYTES: Self = Self(0x0040_0000);

    /// Align section data on a 16-byte boundary.
    pub const ALIGN_16BYTES: Self = Self(0x0050_0000);

    /// Align section data on a 32-byte boundary.
    pub const ALIGN_32BYTES: Self = Self(0x0060_0000);

    /// Align section data on a 64-byte boundary.
    pub const ALIGN_64BYTES: Self = Self(0x0070_0000);

    /// Align section data on a 128-byte boundary.
    pub const ALIGN_128BYTES: Self = Self(0x0080_0000);

    /// Align section data on a 256-byte boundary.
    pub const ALIGN_256BYTES: Self = Self(0x0090_0000);

    /// Align section data on a 512-byte boundary.
    pub const ALIGN_512BYTES: Self = Self(0x00A0_0000);

    /// Align section data on a 1024-byte boundary.
    pub const ALIGN_1024BYTES: Self = Self(0x00B0_0000);

    /// Align section data on a 2048-byte boundary.
    pub const ALIGN_2048BYTES: Self = Self(0x00C0_0000);

    /// Align section data on a 4096-byte boundary.
    pub const ALIGN_4096BYTES: Self = Self(0x00D0_0000);

    /// Align section data on an 8192-byte boundary.
    pub const ALIGN_8192BYTES: Self = Self(0x00E0_0000);

    /// Section contains extended relocations.
    pub const LNK_NRELOC_OVFL: Self = Self(0x0100_0000);

    /// Section can be discarded after use.
    pub const MEM_DISCARDABLE: Self = Self(0x0200_0000);

    /// Section is not cached.
    pub const MEM_NOT_CACHED: Self = Self(0x0400_0000);

    /// Section is not pageable.
    pub const MEM_NOT_PAGED: Self = Self(0x0800_0000);

    /// Section is shared among all processes.
    pub const MEM_SHARED: Self = Self(0x1000_0000);

    /// Section is executable.
    pub const MEM_EXECUTE: Self = Self(0x2000_0000);

    /// Section is readable.
    pub const MEM_READ: Self = Self(0x4000_0000);

    /// Section is writable.
    pub const MEM_WRITE: Self = Self(0x8000_0000);
}

impl_bitflags!(SectionCharacteristics);

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExceptionHandler {
    /// Handle the exception here and unwind.
    ExecuteHandler = 1,

    /// Skip this handler and let Windows keep searching.
    ContinueSearch = 0,

    /// Resume execution at the faulting instruction.
    ContinueExecution = -1,
}
