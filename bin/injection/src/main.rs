use std::{fs, os::windows::prelude::OsStrExt};

use clap::value_parser;
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::{
                Debug::WriteProcessMemory,
                ToolHelp::{
                    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                    TH32CS_SNAPPROCESS,
                },
            },
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{
                VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
            },
            Threading::{CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ALL_ACCESS},
            WindowsProgramming::INFINITE,
        },
    },
};

unsafe fn injection(process_id: u32, path: &Vec<u16>) {
    let process = OpenProcess(PROCESS_ALL_ACCESS, false, process_id).unwrap();
    println!("OpenProcess: {:?}", process);
    let kernel32 = GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0" as _)).unwrap();

    let load_library = GetProcAddress(kernel32, PCSTR::from_raw(b"LoadLibraryW\0" as _));
    println!("LoadLibraryW: {}", load_library.is_some());
    let load_library = *(&load_library as *const _ as *const Option<_>);

    let addr = VirtualAllocEx(
        process,
        None,
        path.len() * 2,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    let r = WriteProcessMemory(process, addr, path.as_ptr() as _, path.len() * 2, None);
    if !r.as_bool() {
        return;
    }
    let result = CreateRemoteThread(process, None, 0, load_library, Some(addr), 0, None).unwrap();
    WaitForSingleObject(result, INFINITE);

    VirtualFreeEx(process, addr, path.len() * 2, MEM_RELEASE);
    CloseHandle(result);
    CloseHandle(process);
    println!("完成");
}

fn main() {
    let cmd = clap::Command::new("Inject DLL")
        .group(clap::ArgGroup::new("process").required(true))
        .arg(clap::Arg::new("name").short('n').group("process"))
        .arg(clap::Arg::new("pid").short('p').value_parser(value_parser!(usize)).group("process"))
        .arg(clap::Arg::new("dll").short('d').required(true))
        .get_matches();
    let path = cmd.get_one::<String>("dll").unwrap();
    let path = fs::canonicalize(path).unwrap();
    if !path.is_file() {
        panic!("Path {:?} is Not a File", path)
    }

    let mut path: Vec<_> = path.as_os_str().encode_wide().collect();
    path.push(0);

    if let Some(process_id) = cmd.get_one::<usize>("pid").copied() {
        unsafe { injection(process_id as _, &path) }
    } else {
        let name = cmd.get_one::<String>("name").expect("无法获取参数: name");
        unsafe { get_process_by_name(name).for_each(|process_id| injection(process_id, &path)) }
    }
}

struct ProcessIter {
    hobject: HANDLE,
    first: bool,
}

impl Drop for ProcessIter {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.hobject) };
    }
}

impl Iterator for ProcessIter {
    type Item = PROCESSENTRY32W;

    #[allow(clippy::field_reassign_with_default)]
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut pe: PROCESSENTRY32W = Default::default();
            pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as _;
            let r = if self.first {
                let r = Process32FirstW(self.hobject, &mut pe);
                self.first = false;
                r
            } else {
                Process32NextW(self.hobject, &mut pe)
            };
            if r.as_bool() {
                Some(pe)
            } else {
                None
            }
        }
    }
}

#[allow(clippy::field_reassign_with_default, clippy::needless_lifetimes)]
unsafe fn get_process_by_name<'a>(name: &'a str) -> impl Iterator<Item = u32> + 'a {
    let hobject = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).unwrap();
    let iter = ProcessIter {
        hobject,
        first: true,
    };
    iter.into_iter().filter_map(move |pe| {
        let str = PCWSTR::from_raw(pe.szExeFile.as_ptr());
        match str.to_string() {
            Ok(s) => {
                println!("Process: {}", s);
                if s.contains(name) {
                    Some(pe.th32ProcessID)
                } else {
                    None
                }
            }
            Err(s) => {
                println!("Process: {}", s);
                None
            }
        }
    })
}
