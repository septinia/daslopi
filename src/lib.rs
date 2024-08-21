use std::{ffi::{c_char, CStr, CString}, ops::{ControlFlow, Range}, sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

use clap::{arg, Parser};
use drillx::equix;
use futures_util::{SinkExt, StreamExt};
use solana_sdk::{signature::{read_keypair_file, Keypair}, signer::Signer};
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::{handshake::client::{generate_key, Request}, Message}};
use base64::prelude::*;
use rayon::prelude::*;
use mine::MineArgs;
pub mod logger;
pub mod mine;

#[no_mangle]
pub extern "C" fn start_logging() -> *mut logger::Logger {
    let logger = logger::Logger::new();
    let logger_ptr = Box::into_raw(Box::new(logger));

    // Example of logging messages
    unsafe {
        (*logger_ptr).log("Logger initialized");
        (*logger_ptr).log("Another log entry");
    }

    logger_ptr
}

#[no_mangle]
pub extern "C" fn my_rust_function(args: *const MineArgs, url: *const c_char, username: *const c_char , logger_ptr: *mut logger::Logger)  {
    let url = unsafe { CStr::from_ptr(url).to_string_lossy().into_owned() };
    let username = unsafe { CStr::from_ptr(username).to_string_lossy().into_owned() };
    let args = unsafe { &*args };


    my_sync_function((*args).clone(), url, username,logger_ptr);
}

#[no_mangle]
pub extern "C" fn clear_logs(logger_ptr: *mut logger::Logger) {
    let logger = unsafe { &*logger_ptr };
    logger.clear_logs();
}

#[no_mangle]
pub extern "C" fn get_logs(logger_ptr: *mut logger::Logger) -> *const c_char {
    let logger = unsafe { &*logger_ptr };
    let logs = logger.get_logs();
    CString::new(logs).unwrap().into_raw()
}

pub fn my_sync_function(args: MineArgs, url: String, username: String , logger_ptr: *mut logger::Logger) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(mine::startMine(args, url, username,logger_ptr));
}

