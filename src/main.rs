#![windows_subsystem = "windows"]

use std::ptr;
use winapi::um::winnt::HANDLE;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::debugapi::IsDebuggerPresent;
use lazy_static::lazy_static;

// Gizli mesajı statik olarak saklayalım
lazy_static! {
    static ref HIDDEN_MESSAGE: String = String::from("Driver başlatıldı");
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
    // Debug kontrolü
    if check_debugger() {
        return;
    }

    println!("{}", *HIDDEN_MESSAGE);

    // Driver işlemleri burada gerçekleştirilecek
    unsafe {
        let process_handle = GetCurrentProcess();
        // Driver işlemleri...

        // İşlem bitince izleri temizle
        clean_memory_traces(process_handle as *mut u8, std::mem::size_of::<HANDLE>());
    }
} 