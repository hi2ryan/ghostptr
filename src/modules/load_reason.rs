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

impl From<LdrDllLoadReason> for ModuleLoadReason {
    fn from(reason: LdrDllLoadReason) -> Self {
        match reason {
            LdrDllLoadReason::Unknown => ModuleLoadReason::Unknown,
            LdrDllLoadReason::StaticDependency => {
                ModuleLoadReason::StaticDependency
            }
            LdrDllLoadReason::StaticForwarderDependency => {
                ModuleLoadReason::StaticForwarderDependency
            }
            LdrDllLoadReason::DynamicForwarderDependency => {
                ModuleLoadReason::DynamicForwarderDependency
            }
            LdrDllLoadReason::DelayloadDependency => {
                ModuleLoadReason::DelayloadDependency
            }
            LdrDllLoadReason::DynamicLoad => ModuleLoadReason::DynamicLoad,
            LdrDllLoadReason::AsImageLoad => ModuleLoadReason::AsImageLoad,
            LdrDllLoadReason::AsDataLoad => ModuleLoadReason::AsDataLoad,
            LdrDllLoadReason::EnclavePrimary => {
                ModuleLoadReason::EnclavePrimary
            }
            LdrDllLoadReason::EnclaveDependency => {
                ModuleLoadReason::EnclaveDependency
            }
            LdrDllLoadReason::PatchImage => ModuleLoadReason::PatchImage,
        }
    }
}

impl From<ModuleLoadReason> for LdrDllLoadReason {
    fn from(reason: ModuleLoadReason) -> Self {
        match reason {
            ModuleLoadReason::Unknown => LdrDllLoadReason::Unknown,
            ModuleLoadReason::StaticDependency => {
                LdrDllLoadReason::StaticDependency
            }
            ModuleLoadReason::StaticForwarderDependency => {
                LdrDllLoadReason::StaticForwarderDependency
            }
            ModuleLoadReason::DynamicForwarderDependency => {
                LdrDllLoadReason::DynamicForwarderDependency
            }
            ModuleLoadReason::DelayloadDependency => {
                LdrDllLoadReason::DelayloadDependency
            }
            ModuleLoadReason::DynamicLoad => LdrDllLoadReason::DynamicLoad,
            ModuleLoadReason::AsImageLoad => LdrDllLoadReason::AsImageLoad,
            ModuleLoadReason::AsDataLoad => LdrDllLoadReason::AsDataLoad,
            ModuleLoadReason::EnclavePrimary => {
                LdrDllLoadReason::EnclavePrimary
            }
            ModuleLoadReason::EnclaveDependency => {
                LdrDllLoadReason::EnclaveDependency
            }
            ModuleLoadReason::PatchImage => LdrDllLoadReason::PatchImage,
        }
    }
}
