use std::{sync::Mutex, ptr::{addr_of, null_mut}};
use windows::{Win32::{System::{Diagnostics::{ToolHelp::{
    CreateToolhelp32Snapshot,
    Module32FirstW,
    Module32NextW,
    MODULEENTRY32W,
    TH32CS_SNAPMODULE
}, Debug::{ImageNtHeader, IMAGE_SECTION_HEADER}}, Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE}}, Foundation::CloseHandle, UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE}}, w, core::PCWSTR};

const ORIGINAL_CERT: &[u8] = include_bytes!("../original.pem");
const OUR_CERT: &[u8] = include_bytes!("../cert.pem");
static X: Mutex<Option<Plugin>> = Mutex::new(None);

#[no_mangle]
extern "C" fn DllMain(_: usize, reason: u32, _: usize) -> bool {
    println!("reason = {reason}");

    match reason {
        0 => { // PROCESS_DETACH
            X.lock().unwrap().take();
        },
        1 => { // PROCESS_ATTACH
            *X.lock().unwrap() = Some(Plugin::new());
        },
        _ => {},
    }
    true
}

fn get_name(ptr: *const u16) -> String {
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }

    let data = unsafe { core::slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(data)
}

fn mbox(msg: &str) {
    unsafe {
        let msg = msg.encode_utf16().chain(core::iter::once(0)).collect::<Vec<u16>>();
        MessageBoxW(None, PCWSTR::from_raw(msg.as_ptr()), w!("Caption"), MESSAGEBOX_STYLE::default());
    }
}

unsafe fn find_in_image(base: usize, needle: &[u8]) -> Option<usize> {
    let nt_image = ImageNtHeader(base as _);
    let section_addr_start = addr_of!((*nt_image).OptionalHeader) as usize + (*nt_image).FileHeader.SizeOfOptionalHeader as usize;
    let sections = core::slice::from_raw_parts(section_addr_start as *const IMAGE_SECTION_HEADER, (*nt_image).FileHeader.NumberOfSections as usize);
    for section in sections {
        let section_data = core::slice::from_raw_parts((base + section.VirtualAddress as usize) as *const u8, section.Misc.VirtualSize as usize);
        if ORIGINAL_CERT.len() > section_data.len() {
            continue;
        }
        for idx in 0..section_data.len()-needle.len() {
            let scope = &section_data[idx..][..needle.len()];
            if scope == needle {
                let cert_data_addr = addr_of!(section_data[idx]);
                return Some(cert_data_addr as usize);
            }
        }
    }

    None
}

unsafe fn find_ida64() -> Option<(usize, usize)> {
    let handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0).unwrap();

    let mut entry = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as _,
        ..Default::default()
    };

    if !Module32FirstW(handle, &mut entry).as_bool() {
        CloseHandle(handle);
        return None;
    }

    loop {
        let base = entry.modBaseAddr as usize;
        // let len = entry.modBaseSize as usize;

        let name = get_name(entry.szModule.as_ptr());
        if name == "ida64.dll" {
            // let data = core::slice::from_raw_parts(base as *const u8, len);
            // mbox(&format!("Found ida64.dll {base:08x}: {:02x?}", &data[..8]));

            if let Some(cert_addr) = find_in_image(base, ORIGINAL_CERT) {
                let needle = cert_addr.to_ne_bytes();

                // let cert_addr = cert_addr as *const u8;
                // mbox(&format!("found cert @ {cert_addr:p}"));

                if let Some(ptr_addr) = find_in_image(base, &needle) {
                    mbox(&format!("found ptr @ {:p}", ptr_addr as *const u8));

                    let cert = OUR_CERT.to_vec();
                    let cert = Vec::leak(cert);
                    let cert_addr = cert.as_ptr() as usize;

                    let mut old_flags = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS::default();
                    if VirtualProtect(ptr_addr as _, 8, PAGE_EXECUTE_READWRITE, &mut old_flags).as_bool() {
                        core::ptr::write_unaligned(ptr_addr as *mut usize, cert_addr);

                        VirtualProtect(ptr_addr as _, 8, old_flags, null_mut());
                    }
                }
            }

        }

        if !Module32NextW(handle, &mut entry).as_bool() {
            break;
        }
    }

    CloseHandle(handle);

    None
}

struct Plugin {
    
}
impl Plugin {
    pub fn new() -> Self {
        unsafe { find_ida64(); }
        Self {}
    }

}
impl Drop for Plugin {
    fn drop(&mut self) {
        // TODO: Restore original certificate pointer.
    }
}