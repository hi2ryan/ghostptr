use crate::windows::structs::LdrDllLoadReason;

/// Represents the reasoning behind why a module was loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleLoadReason {
    /// The load reason is unknown.
    Unknown,
    /// Loaded because it is a static dependency of another module.
    StaticDependency,
    /// Loaded because it is a static forwarder dependency.
    StaticForwarderDependency,
    /// Loaded because it is a dynamic forwarder dependency.
    DynamicForwarderDependency,
    /// Loaded because it is a delay-loaded dependency.
    DelayloadDependency,
    /// Loaded explicitly via `LoadLibrary` or similar dynamic loading.
    DynamicLoad,
    /// Loaded as an image (typical normal module load).
    AsImageLoad,
    /// Loaded as data, not as a module image.
    AsDataLoad,
    /// Primary module for an enclave (Windows REDSTONE3+).
    EnclavePrimary,
    /// Dependency module for an enclave.
    EnclaveDependency,
    /// Loaded as a patch image (Windows 11+).
    PatchImage,
}

impl ModuleLoadReason {
    /// Returns the raw `LdrDllLoadReason` value ([`i32`]).
    pub fn as_raw(&self) -> i32 {
        LdrDllLoadReason::from(*self) as i32
    }
}

macro_rules! bidirectional_from {
    ($a:ty, $b:ty, [$($variant:ident),* $(,)?]) => {
        impl From<$b> for $a {
            fn from(value: $b) -> Self {
                match value {
                    $(<$b>::$variant => <$a>::$variant,)*
                }
            }
        }
        impl From<$a> for $b {
            fn from(value: $a) -> Self {
                match value {
                    $(<$a>::$variant => <$b>::$variant,)*
                }
            }
        }
    };
}

bidirectional_from!(
    ModuleLoadReason,
    LdrDllLoadReason,
    [
        Unknown,
        StaticDependency,
        StaticForwarderDependency,
        DynamicForwarderDependency,
        DelayloadDependency,
        DynamicLoad,
        AsImageLoad,
        AsDataLoad,
        EnclavePrimary,
        EnclaveDependency,
        PatchImage,
    ]
);
