use windows::{h, Win32::System::LibraryLoader::LoadLibraryW};

fn main() {
    unsafe {
        let a = LoadLibraryW(h!("winmm.dll")).unwrap();
        println!("{:?}", a)
    };
}
