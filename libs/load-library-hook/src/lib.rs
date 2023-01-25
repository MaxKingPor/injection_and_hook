use std::{ffi::c_void, thread};

use windows::{
    core::{HSTRING, PCSTR, PCWSTR},
    Win32::{
        Foundation::{HANDLE, HINSTANCE},
        System::{
            LibraryLoader::{
                DisableThreadLibraryCalls, GetModuleHandleW, GetProcAddress, LoadLibraryW,
                LOAD_LIBRARY_FLAGS,
            },
            SystemServices::{
                DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
            },
        },
    },
};

type HookLoadLibraryAFn =
    unsafe extern "system" fn(lplibfilename: ::windows::core::PCSTR) -> HINSTANCE;
type HookLoadLibraryA = Option<detour::GenericDetour<HookLoadLibraryAFn>>;
static mut HOOK_LOAD_LIBRARY_A: HookLoadLibraryA = None;

#[allow(clippy::missing_safety_doc)]
pub unsafe extern "system" fn hook_load_library_a(
    lplibfilename: ::windows::core::PCSTR,
) -> HINSTANCE {
    println!("LoadLibraryA: {}", lplibfilename.display());
    let r = HOOK_LOAD_LIBRARY_A.as_ref().unwrap().call(lplibfilename);
    r
}

type HookLoadLibraryWFn =
    unsafe extern "system" fn(lplibfilename: ::windows::core::PCWSTR) -> HINSTANCE;
type HookLoadLibraryW = Option<detour::GenericDetour<HookLoadLibraryWFn>>;
static mut HOOK_LOAD_LIBRARY_W: HookLoadLibraryW = None;

#[allow(clippy::missing_safety_doc)]
pub unsafe extern "system" fn hook_load_library_w(
    lplibfilename: ::windows::core::PCWSTR,
) -> HINSTANCE {
    println!("LoadLibraryW: {}", lplibfilename.display());
    let r = HOOK_LOAD_LIBRARY_W.as_ref().unwrap().call(lplibfilename);
    r
}

type HookLoadLibraryExAFn = unsafe extern "system" fn(
    lplibfilename: PCSTR,
    hfile: HANDLE,
    dwflags: LOAD_LIBRARY_FLAGS,
) -> HINSTANCE;
type HookLoadLibraryExA = Option<detour::GenericDetour<HookLoadLibraryExAFn>>;
static mut HOOK_LOAD_LIBRARY_EX_A: HookLoadLibraryExA = None;

#[allow(clippy::missing_safety_doc)]
pub unsafe extern "system" fn hook_load_library_ex_a(
    lplibfilename: PCSTR,
    hfile: HANDLE,
    dwflags: LOAD_LIBRARY_FLAGS,
) -> HINSTANCE {
    println!("LoadLibraryExA: {}", lplibfilename.display());
    let r = HOOK_LOAD_LIBRARY_EX_A
        .as_ref()
        .unwrap()
        .call(lplibfilename, hfile, dwflags);
    r
}

type HookLoadLibraryExWFn = unsafe extern "system" fn(
    lplibfilename: PCWSTR,
    hfile: HANDLE,
    dwflags: LOAD_LIBRARY_FLAGS,
) -> HINSTANCE;
type HookLoadLibraryExW = Option<detour::GenericDetour<HookLoadLibraryExWFn>>;
static mut HOOK_LOAD_LIBRARY_EX_W: HookLoadLibraryExW = None;

#[allow(clippy::missing_safety_doc)]
pub unsafe extern "system" fn hook_load_library_ex_w(
    lplibfilename: PCWSTR,
    hfile: HANDLE,
    dwflags: LOAD_LIBRARY_FLAGS,
) -> HINSTANCE {
    println!("LoadLibraryExW: {}", lplibfilename.display());
    let r = HOOK_LOAD_LIBRARY_EX_W
        .as_ref()
        .unwrap()
        .call(lplibfilename, hfile, dwflags);
    r
}

#[no_mangle]
#[allow(clippy::missing_safety_doc, non_snake_case, unused)]
pub unsafe extern "system" fn DllMain(
    hinstDLL: HINSTANCE,
    fdwReason: u32,
    lpvReserved: *const c_void,
) -> bool {
    match fdwReason {
        DLL_PROCESS_ATTACH => {
            let r = DisableThreadLibraryCalls(hinstDLL);

            thread::spawn(|| {
                let dllname = HSTRING::from("kernel32.dll\0");
                let dll = GetModuleHandleW(&dllname).unwrap_or_else(|_e| {
                    println!("LoadLibraryA");
                    LoadLibraryW(&dllname).unwrap()
                });

                {
                    // LoadLibraryA
                    let wsasend = GetProcAddress(dll, PCSTR::from_raw(b"LoadLibraryA\0" as _));
                    println!("LoadLibraryA is {}", wsasend.is_some());
                    let a = *(&wsasend as *const _ as *const Option<HookLoadLibraryAFn>);
                    let _hook = detour::GenericDetour::<HookLoadLibraryAFn>::new(
                        a.unwrap(),
                        hook_load_library_a as HookLoadLibraryAFn,
                    )
                    .unwrap();
                    _hook.enable().unwrap();
                    HOOK_LOAD_LIBRARY_A = Some(_hook);
                }

                {
                    // LoadLibraryW
                    let wsasend = GetProcAddress(dll, PCSTR::from_raw(b"LoadLibraryW\0" as _));
                    println!("LoadLibraryW is {}", wsasend.is_some());
                    let a = *(&wsasend as *const _ as *const Option<HookLoadLibraryWFn>);
                    let _hook = detour::GenericDetour::<HookLoadLibraryWFn>::new(
                        a.unwrap(),
                        hook_load_library_w as HookLoadLibraryWFn,
                    )
                    .unwrap();
                    _hook.enable().unwrap();
                    HOOK_LOAD_LIBRARY_W = Some(_hook);
                }

                {
                    // LoadLibraryExA
                    let wsasend = GetProcAddress(dll, PCSTR::from_raw(b"LoadLibraryExA\0" as _));
                    println!("LoadLibraryExA is {}", wsasend.is_some());
                    let a = &wsasend as *const _;
                    let a = *(&wsasend as *const _ as *const Option<HookLoadLibraryExAFn>);
                    let _hook = detour::GenericDetour::<HookLoadLibraryExAFn>::new(
                        a.unwrap(),
                        hook_load_library_ex_a as HookLoadLibraryExAFn,
                    )
                    .unwrap();
                    _hook.enable().unwrap();
                    HOOK_LOAD_LIBRARY_EX_A = Some(_hook);
                }

                {
                    // LoadLibraryExW
                    let wsasend = GetProcAddress(dll, PCSTR::from_raw(b"LoadLibraryExW\0" as _));
                    println!("LoadLibraryExW is {}", wsasend.is_some());
                    let a = *(&wsasend as *const _ as *const Option<HookLoadLibraryExWFn>);
                    let _hook = detour::GenericDetour::<HookLoadLibraryExWFn>::new(
                        a.unwrap(),
                        hook_load_library_ex_w as HookLoadLibraryExWFn,
                    )
                    .unwrap();
                    _hook.enable().unwrap();
                    HOOK_LOAD_LIBRARY_EX_W = Some(_hook);
                }

                // CloseHandle(dll);
            });
        }
        DLL_PROCESS_DETACH => {}
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => panic!(),
    };

    true
}
