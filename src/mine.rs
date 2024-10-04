
use std::{ops::{ControlFlow, Range}, sync::Arc, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use clap::{arg, Parser};
use drillx_2::equix::SolverMemory;
use tor_c_equix;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc::UnboundedSender, Mutex};
use tokio_tungstenite::{connect_async, tungstenite::{handshake::client::{generate_key, Request}, Message}};
use base64::prelude::*;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::watch;
use sha3::Digest;

#[derive(Debug)]
pub enum ServerMessage {
    StartMining([u8; 32], Range<u64>, u64)
}

#[derive(Debug, Parser)]
pub struct MineArgs {
    #[arg(
        long,
        value_name = "CORES",
        default_value = "1",
        help = "Number of cores to use while mining"
    )]
    pub cores: u32,

    #[arg(
        long,
        value_name = "Hash mode",
        default_value = "1",
        help = "Old=1 , New=2"
    )]
    pub mode: u32,

    #[arg(
        long,
        value_name = "Idle check",
        default_value = "60",
        help = "Set time in seconds for miner to auto-restart if the miner is idling for more than x seconds"
    )]
    pub idle: u32,
}

fn u16_to_u8_array(input: [u16; 8]) -> [u8; 16] {
    let mut output = [0u8; 16];
    unsafe {
        for i in 0..8 {
            *output.get_unchecked_mut(i * 2) = (input[i] & 0xFF) as u8;
            *output.get_unchecked_mut(i * 2 + 1) = (input[i] >> 8) as u8;
        }
    }
    output
}

fn hashv(digest: &[u8; 16], nonce: &[u8; 8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(&sorted(*digest));
    hasher.update(nonce);
    hasher.finalize().into()
}

fn sorted(mut digest: [u8; 16]) -> [u8; 16] {
    unsafe {
        let u16_slice: &mut [u16; 8] = core::mem::transmute(&mut digest);
        u16_slice.sort_unstable();
        digest
    }
}

pub fn c_equix(cell:&std::cell::RefCell<tor_c_equix::EquiX> ,challenge: [u8; 32],nonce:[u8; 8]) -> Vec<drillx_2::Hash> {
    let mut hashes: Vec<drillx_2::Hash> = Vec::with_capacity(8);
    let seed: [u8; 40] = drillx_2::seed(&challenge, &nonce);

    let mut buffer: tor_c_equix::EquiXSolutionsBuffer = Default::default();
    cell.borrow_mut().solve(&seed, &mut buffer);
    for i in 0..buffer.count {
        let sol = buffer.sols[i as usize];
        let u8: [u8; 16] = u16_to_u8_array(sol.idx);
        let dh = drillx_2::Hash {
            d: u8,
            h: hashv(&u8, &nonce),
        };
        hashes.push(dh);
    }

    hashes
}

pub async fn mine(args: MineArgs, url: String , username: String)  {
    loop {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let is_cancelled = Arc::new(AtomicBool::new(false));
        let last_activity = Arc::new(Mutex::new(Instant::now()));

        let url = url::Url::parse(&url).expect("Failed to parse server url");
        let host = url.host_str().expect("Invalid host in server url");
        let threads = args.cores;
        let mode: u32 = args.mode;
        let idle_time: u32 = args.idle;

        let version = env!("CARGO_PKG_VERSION");
        let auth = BASE64_STANDARD.encode(format!("{}/{}", username,version));

        println!("Connecting to server...");
        let request = Request::builder()
            .method("GET")
            .uri(url.to_string())
            .header("Sec-Websocket-Key", generate_key())
            .header("Host", host)
            .header("Upgrade", "websocket")
            .header("Connection", "upgrade")
            .header("Sec-Websocket-Version", "13")
            .header("Authorization", format!("Basic {}", auth))
            .body(())
            .unwrap();

        match connect_async(request).await {
            Ok((ws_stream, _)) => {
                println!("Connected to network!");

                let (sender, mut receiver) = ws_stream.split();
                let sender = Arc::new(Mutex::new(sender));
                let (message_sender, mut message_receiver) = tokio::sync::mpsc::unbounded_channel::<ServerMessage>();

                let is_cancelled_clone = Arc::clone(&is_cancelled);
                let last_activity_clone = Arc::clone(&last_activity);
                *last_activity_clone.lock().await = Instant::now();

                let receiver_thread = tokio::spawn(async move {
                    while let Some(Ok(message)) = receiver.next().await {
                        if process_message(message, message_sender.clone()).is_break() {
                            break;
                        }
                    }
                    let _ = cancel_tx.send(true);
                    is_cancelled_clone.store(true, Ordering::SeqCst);
                });

                let idle_timeout_clone = Arc::clone(&last_activity);
                let sender_clone = Arc::clone(&sender);
                let is_cancelled_clone = Arc::clone(&is_cancelled);
                let idle_check_thread = tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(10)); // Check every second
                    let is_cancelled = is_cancelled_clone.clone();
                    loop {
                        interval.tick().await;
                        let last_activity_time = *idle_timeout_clone.lock().await;
                        if is_cancelled.load(Ordering::SeqCst) {
                            break
                        }
                        if last_activity_time.elapsed().as_secs() >= (idle_time  as u64) {
                            println!("Idle for too long, disconnecting and reconnecting...");
                            let mut sender = sender_clone.lock().await;
                            let _ = sender.send(Message::Close(None)).await;
                            break;
                        }
                    }
                });

                // receive messages
                let message_sender = Arc::clone(&sender);
                while let Some(msg) = message_receiver.recv().await {
                    match msg {
                        ServerMessage::StartMining(challenge, nonce_range, cutoff) => {
                            *last_activity_clone.lock().await = Instant::now();
                            println!("Received start mining message , Nonce range: {} - {}", nonce_range.start, nonce_range.end);
                            let hash_timer = Instant::now();
                            let nonces_per_thread = 10_000;

                            let is_cancelled_clone = Arc::clone(&is_cancelled);
                            let rt: tokio::runtime::Handle = tokio::runtime::Handle::current();

                            let handles: Vec<_> = (0..threads)
                            .into_par_iter()
                            .map(|i| {
                                rt.spawn_blocking({
                                    let is_cancelled = is_cancelled_clone.clone();
                                    move || {
                                            let solve = tor_c_equix::EquiXFlags::EQUIX_CTX_SOLVE;
                                            let comp = tor_c_equix::EquiXFlags::EQUIX_CTX_TRY_COMPILE;
                                            let mem = tor_c_equix::EquiX::new(solve | comp);
                                            let ctx_cell: std::cell::RefCell<tor_c_equix::EquiX> = std::cell::RefCell::new(mem);
                                            let mut memory = SolverMemory::new();

                                            let first_nonce: u64 = nonce_range.start + (nonces_per_thread * (i as u64));
                                            let mut nonce = first_nonce;
                                            let mut best_nonce = nonce;
                                            let mut best_difficulty = 0;
                                            let mut best_hash = drillx_2::Hash::default();
                                            let mut total_hashes: u64 = 0;

                                            loop {
                                                if is_cancelled.load(Ordering::SeqCst) {
                                                    return None;
                                                }
                                                // Create hash
                                                let hashes : Vec<drillx_2::Hash>;
                                                if mode == 1 {
                                                    hashes = drillx_2::get_hashes_with_memory(&mut memory, &challenge, &nonce.to_le_bytes());
                                                } else {
                                                    hashes = c_equix(&ctx_cell ,challenge,nonce.to_le_bytes());
                                                }
                                                for hx in hashes {  
                                                    total_hashes += 1;
                                                    let difficulty = hx.difficulty();
                                                    if difficulty.gt(&best_difficulty) {
                                                        best_nonce = nonce;
                                                        best_difficulty = difficulty;
                                                        best_hash = hx;
                                                    }
                                                }

                                                // Exit if processed nonce range
                                                if nonce >= nonce_range.end {
                                                    break;
                                                }

                                                if hash_timer.elapsed().as_secs().ge(&cutoff) {
                                                    break;
                                                }


                                                // Increment nonce
                                                nonce += 1;

                                                //should not happen
                                                if hash_timer.elapsed().as_secs().ge(&70) {
                                                    break;
                                                }
                                            }
                                            // Return the best nonce
                                            Some((best_nonce, best_difficulty, best_hash, total_hashes))
                                        }
                                    })
                                })
                                .collect();

                                let mut total = 0;
                                let joined = futures::future::join_all(handles).await;

                                let (best_nonce, best_difficulty, best_hash , total_nonces_checked) = joined.into_iter().fold(
                                    (0, 0, drillx_2::Hash::default(),0),
                                    |(best_nonce, best_difficulty, best_hash ,total_nonces_checked ), h: Result<Option<(u64, u32, drillx_2::Hash, u64)>, tokio::task::JoinError>| {
                                        if let Ok(Some((nonce, difficulty, hash, checked))) = h {
                                            total += checked;
                                            if difficulty > best_difficulty {
                                                (nonce, difficulty, hash , checked)
                                            } else {
                                                (best_nonce, best_difficulty, best_hash , total_nonces_checked)
                                            }
                                        } else {
                                            (0, 0, drillx_2::Hash::default(),0)
                                        }
                                    },
                                );

                            let hash_time = hash_timer.elapsed();

                            println!("Found best diff: {} , Processed:{} , Hash time:{:?} , Hashrate:{:.3} k", best_difficulty,total,hash_time , ((total as f32)/hash_time.as_secs_f32())/1000.0 );

                            let message_type =  2u8; // 1 u8 - BestSolution Message
                            let best_hash_bin = best_hash.d; // 16 u8
                            let best_nonce_bin = best_nonce.to_le_bytes(); // 8 u8
                            
                            let mut hash_nonce_message = [0; 24];
                            hash_nonce_message[0..16].copy_from_slice(&best_hash_bin);
                            hash_nonce_message[16..24].copy_from_slice(&best_nonce_bin);

                            let mut bin_data = [0; 57];
                            bin_data[00..1].copy_from_slice(&message_type.to_le_bytes());
                            bin_data[01..17].copy_from_slice(&best_hash_bin);
                            bin_data[17..25].copy_from_slice(&best_nonce_bin);

                            let bin_vec = bin_data.to_vec();

                            {
                                let mut message_sender = message_sender.lock().await;
                                let _ = message_sender.send(Message::Binary(bin_vec)).await;
                            }

                            tokio::time::sleep(Duration::from_millis(100)).await;
                            // send new Ready message

                            let mut bin_data: Vec<u8> = Vec::new();
                            bin_data.push(0u8);
                            {
                                *last_activity_clone.lock().await = Instant::now();
                                let mut message_sender = message_sender.lock().await;
                                let _ = message_sender.send(Message::Binary(bin_data)).await;
                            }
                        }
                    }
                }

                let _ = receiver_thread.await;
                // let _ = idle_check_thread.await;
            }, 
            Err(e) => {
                match e {
                    tokio_tungstenite::tungstenite::Error::Http(e) => {
                        if let Some(body) = e.body() {
                            println!("Error: {:?}", String::from_utf8(body.to_vec()));
                        } else {
                            println!("Http Error: {:?}", e);
                        }
                    }, 
                    _ => {
                        println!("Error: {:?}", e);
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}

fn process_message(msg: Message, message_channel: UnboundedSender<ServerMessage>) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t)=>{
            println!("\n>>> Server Message: \n{}\n",t);
        },
        Message::Binary(b) => {
            let message_type = b[0];
            match message_type {
                    0 => {
                        if b.len() < 49 {
                            println!("Invalid data for Message StartMining");
                        } else {
                            let mut hash_bytes = [0u8; 32];
                            // extract 256 bytes (32 u8's) from data for hash
                            let mut b_index = 1;
                            for i in 0..32 {
                                hash_bytes[i] = b[i + b_index];
                            }
                            b_index += 32;

                            // extract 64 bytes (8 u8's)
                            let mut cutoff_bytes = [0u8; 8];
                            for i in 0..8 {
                                cutoff_bytes[i] = b[i + b_index];
                            }
                            b_index += 8;
                            let cutoff = u64::from_le_bytes(cutoff_bytes);

                            let mut nonce_start_bytes = [0u8; 8];
                            for i in 0..8 {
                                nonce_start_bytes[i] = b[i + b_index];
                            }
                            b_index += 8;
                            let nonce_start = u64::from_le_bytes(nonce_start_bytes);

                            let mut nonce_end_bytes = [0u8; 8];
                            for i in 0..8 {
                                nonce_end_bytes[i] = b[i + b_index];
                            }
                            let nonce_end = u64::from_le_bytes(nonce_end_bytes);

                            let msg = ServerMessage::StartMining(hash_bytes, nonce_start..nonce_end, cutoff);

                            let _ = message_channel.send(msg);
                        }

                    },
                    _ => {
                        println!("Failed to parse server message type");
                    }
                }

        },
        Message::Ping(v) => {println!("Got Ping: {:?}", v);}, 
        Message::Pong(v) => {println!("Got Pong: {:?}", v);}, 
        Message::Close(v) => {
            println!("Got Close: {:?}", v);
            return ControlFlow::Break(());
        }, 
        _ => {println!("Got invalid message data");}
    }

    ControlFlow::Continue(())
}
