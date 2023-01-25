// #![allow(non_snake_case, unused)]

use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    slice, thread,
};

use windows::{
    core::{HSTRING, PCSTR, PCWSTR},
    Win32::{
        Foundation::HINSTANCE,
        Networking::WinSock::{LPWSAOVERLAPPED_COMPLETION_ROUTINE, SOCKET, WSABUF},
        System::{
            LibraryLoader::{FreeLibrary, GetModuleHandleW, GetProcAddress, LoadLibraryW},
            SystemInformation::GetSystemDirectoryW,
            SystemServices::{
                DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
            },
            IO::OVERLAPPED,
        },
    },
};

mod winmm;
pub use winmm::*;

static mut M_H_MODULE: HINSTANCE = HINSTANCE(0);

static mut HOOKS: Option<Vec<detour::GenericDetour<unsafe extern "system" fn() -> isize>>> = None;
static mut FILE: Option<File> = None;
// unsafe fn get_export_table(hModule: HINSTANCE) {}

#[allow(clippy::all)]
unsafe fn init_function(h_module: HINSTANCE) {
    let mut buf = [0; 0xFF];
    GetSystemDirectoryW(Some(&mut buf));
    let str = PCWSTR::from_raw(buf.as_ptr());
    let s = str.to_string().unwrap();
    let path = PathBuf::from(s).join("winmm.dll");
    let a = HSTRING::from(path.as_path());
    let a = PCWSTR::from_raw(a.as_ptr());
    let m_h_module = GetModuleHandleW(a).unwrap_or_else(|_err| LoadLibraryW(a).unwrap());

    M_H_MODULE = m_h_module;
    println!("{:?}, {:?}", path, m_h_module);

    let psz_proc_name = [
        "CloseDriver",
        "DefDriverProc",
        "DriverCallback",
        "DrvGetModuleHandle",
        "GetDriverModuleHandle",
        "NotifyCallbackData",
        "OpenDriver",
        "PlaySound",
        "PlaySoundA",
        "PlaySoundW",
        "SendDriverMessage",
        "WOW32DriverCallback",
        "WOW32ResolveMultiMediaHandle",
        "WOWAppExit",
        "aux32Message",
        "auxGetDevCapsA",
        "auxGetDevCapsW",
        "auxGetNumDevs",
        "auxGetVolume",
        "auxOutMessage",
        "auxSetVolume",
        "joy32Message",
        "joyConfigChanged",
        "joyGetDevCapsA",
        "joyGetDevCapsW",
        "joyGetNumDevs",
        "joyGetPos",
        "joyGetPosEx",
        "joyGetThreshold",
        "joyReleaseCapture",
        "joySetCapture",
        "joySetThreshold",
        "mci32Message",
        "mciDriverNotify",
        "mciDriverYield",
        "mciExecute",
        "mciFreeCommandResource",
        "mciGetCreatorTask",
        "mciGetDeviceIDA",
        "mciGetDeviceIDFromElementIDA",
        "mciGetDeviceIDFromElementIDW",
        "mciGetDeviceIDW",
        "mciGetDriverData",
        "mciGetErrorStringA",
        "mciGetErrorStringW",
        "mciGetYieldProc",
        "mciLoadCommandResource",
        "mciSendCommandA",
        "mciSendCommandW",
        "mciSendStringA",
        "mciSendStringW",
        "mciSetDriverData",
        "mciSetYieldProc",
        "mid32Message",
        "midiConnect",
        "midiDisconnect",
        "midiInAddBuffer",
        "midiInClose",
        "midiInGetDevCapsA",
        "midiInGetDevCapsW",
        "midiInGetErrorTextA",
        "midiInGetErrorTextW",
        "midiInGetID",
        "midiInGetNumDevs",
        "midiInMessage",
        "midiInOpen",
        "midiInPrepareHeader",
        "midiInReset",
        "midiInStart",
        "midiInStop",
        "midiInUnprepareHeader",
        "midiOutCacheDrumPatches",
        "midiOutCachePatches",
        "midiOutClose",
        "midiOutGetDevCapsA",
        "midiOutGetDevCapsW",
        "midiOutGetErrorTextA",
        "midiOutGetErrorTextW",
        "midiOutGetID",
        "midiOutGetNumDevs",
        "midiOutGetVolume",
        "midiOutLongMsg",
        "midiOutMessage",
        "midiOutOpen",
        "midiOutPrepareHeader",
        "midiOutReset",
        "midiOutSetVolume",
        "midiOutShortMsg",
        "midiOutUnprepareHeader",
        "midiStreamClose",
        "midiStreamOpen",
        "midiStreamOut",
        "midiStreamPause",
        "midiStreamPosition",
        "midiStreamProperty",
        "midiStreamRestart",
        "midiStreamStop",
        "mixerClose",
        "mixerGetControlDetailsA",
        "mixerGetControlDetailsW",
        "mixerGetDevCapsA",
        "mixerGetDevCapsW",
        "mixerGetID",
        "mixerGetLineControlsA",
        "mixerGetLineControlsW",
        "mixerGetLineInfoA",
        "mixerGetLineInfoW",
        "mixerGetNumDevs",
        "mixerMessage",
        "mixerOpen",
        "mixerSetControlDetails",
        "mmDrvInstall",
        "mmGetCurrentTask",
        "mmTaskBlock",
        "mmTaskCreate",
        "mmTaskSignal",
        "mmTaskYield",
        "mmioAdvance",
        "mmioAscend",
        "mmioClose",
        "mmioCreateChunk",
        "mmioDescend",
        "mmioFlush",
        "mmioGetInfo",
        "mmioInstallIOProcA",
        "mmioInstallIOProcW",
        "mmioOpenA",
        "mmioOpenW",
        "mmioRead",
        "mmioRenameA",
        "mmioRenameW",
        "mmioSeek",
        "mmioSendMessage",
        "mmioSetBuffer",
        "mmioSetInfo",
        "mmioStringToFOURCCA",
        "mmioStringToFOURCCW",
        "mmioWrite",
        "mmsystemGetVersion",
        "mod32Message",
        "mxd32Message",
        "sndPlaySoundA",
        "sndPlaySoundW",
        "tid32Message",
        "timeBeginPeriod",
        "timeEndPeriod",
        "timeGetDevCaps",
        "timeGetSystemTime",
        "timeGetTime",
        "timeKillEvent",
        "timeSetEvent",
        "waveInAddBuffer",
        "waveInClose",
        "waveInGetDevCapsA",
        "waveInGetDevCapsW",
        "waveInGetErrorTextA",
        "waveInGetErrorTextW",
        "waveInGetID",
        "waveInGetNumDevs",
        "waveInGetPosition",
        "waveInMessage",
        "waveInOpen",
        "waveInPrepareHeader",
        "waveInReset",
        "waveInStart",
        "waveInStop",
        "waveInUnprepareHeader",
        "waveOutBreakLoop",
        "waveOutClose",
        "waveOutGetDevCapsA",
        "waveOutGetDevCapsW",
        "waveOutGetErrorTextA",
        "waveOutGetErrorTextW",
        "waveOutGetID",
        "waveOutGetNumDevs",
        "waveOutGetPitch",
        "waveOutGetPlaybackRate",
        "waveOutGetPosition",
        "waveOutGetVolume",
        "waveOutMessage",
        "waveOutOpen",
        "waveOutPause",
        "waveOutPrepareHeader",
        "waveOutReset",
        "waveOutRestart",
        "waveOutSetPitch",
        "waveOutSetPlaybackRate",
        "waveOutSetVolume",
        "waveOutUnprepareHeader",
        "waveOutWrite",
        "wid32Message",
        "wod32Message",
    ];

    let hooks: Vec<_> = psz_proc_name
        .into_iter()
        .filter_map(|item| unsafe {
            // let cstr = CString::new(item).unwrap();
            // let name = PCSTR::from_raw(cstr.as_ptr() as _);

            let mut a = Vec::from(item);
            a.push(0); // C 字符串0结束
            let name = PCSTR::from_raw(a.as_ptr());

            let lf_address = GetProcAddress(h_module, name);
            let fp_address = GetProcAddress(m_h_module, name);
            println!(
                "{} 劫持DLL:{:?}, 系統Dll: {:?}",
                item,
                lf_address.is_some(),
                fp_address.is_some()
            );
            if let (Some(lf_address), Some(fp_address)) = (lf_address, fp_address) {
                let a = detour::GenericDetour::new(lf_address, fp_address).unwrap();
                a.enable().unwrap();
                println!("Hook: {}", item);
                Some(a)
            } else {
                None
            }
        })
        .collect();

    HOOKS = Some(hooks)
}

type WSASendFN = unsafe extern "system" fn(
    s: SOCKET,
    lpbuffers: *const WSABUF,
    dwbuffercount: usize,
    lpnumberofbytessent: *mut usize,
    dwflags: usize,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32;
type HookWSASendFN = Option<detour::GenericDetour<WSASendFN>>;
static mut HOOK_WSASEND_FN: HookWSASendFN = None;

unsafe extern "system" fn my_wsasend_fn(
    s: SOCKET,
    lpbuffers: *const WSABUF,
    dwbuffercount: usize,
    lpnumberofbytessent: *mut usize,
    dwflags: usize,
    lpoverlapped: *mut OVERLAPPED,
    lpcompletionroutine: LPWSAOVERLAPPED_COMPLETION_ROUTINE,
) -> i32 {
    let data = slice::from_raw_parts(lpbuffers, dwbuffercount as _);

    data.iter().for_each(|item| {
        item.buf
            .to_string()
            .map(|item| {
                FILE.as_mut()
                    .unwrap()
                    .write_fmt(format_args!(
                        "\nSocket {socket} 封包: \n{head}\nSocket {socket} 结束\n",
                        socket = s.0,
                        head = item
                    ))
                    .unwrap();
            })
            .unwrap_or(());
    });
    println!("############################################################");
    HOOK_WSASEND_FN.as_ref().unwrap().call(
        s,
        lpbuffers,
        dwbuffercount,
        lpnumberofbytessent,
        dwflags,
        lpoverlapped,
        lpcompletionroutine,
    )
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: u32,
    _lpv_reserved: *const c_void,
) -> bool {
    match fdw_reason {
        DLL_PROCESS_ATTACH => {
            thread::spawn(|| unsafe {
                println!("############################################################");
                let file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("D:\\Download\\aaa.txt")
                    .unwrap();
                FILE = Some(file);
                let a = HSTRING::from("ws2_32.dll");
                let ws2_32 = GetModuleHandleW(&a).unwrap_or_else(|_err| LoadLibraryW(&a).unwrap());
                let a = GetProcAddress(ws2_32, PCSTR::from_raw(b"WSASend\0" as _));
                println!("WSASend is {}", a.is_some());
                let a = *(&a as *const _ as *const Option<WSASendFN>);
                let _hook =
                    detour::GenericDetour::<WSASendFN>::new(a.unwrap(), my_wsasend_fn as WSASendFN)
                        .unwrap();
                _hook.enable().unwrap();
                HOOK_WSASEND_FN = Some(_hook);
            });
            init_function(hinst_dll);
        }
        DLL_PROCESS_DETACH => {
            if let Some(ref v) = HOOKS {
                v.iter().for_each(|item| item.disable().unwrap())
            }
            FreeLibrary(M_H_MODULE);
        }
        DLL_THREAD_ATTACH => {}
        DLL_THREAD_DETACH => {}
        _ => panic!(),
    };
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        unsafe {
            init_function(Default::default());
        }
    }
}
