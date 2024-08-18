use solana_sdk::signature::read_keypair_file;
use clap::{Parser, Subcommand};

use mine::MineArgs;
use signup::signup;

mod signup;
mod mine;
use hostname::get;

// --------------------------------

/// A command line interface tool for pooling power to submit hashes for proportional ORE rewards
#[derive(Parser, Debug)]
#[command(version, author, about, long_about = None)]
struct Args {
    #[arg(long,
        value_name = "SERVER_URL",
        help = "URL of the server to connect to",
        default_value = "domainexpansion.tech",
    )]
    url: String,

    // #[arg(
    //     long,
    //     value_name = "KEYPAIR_PATH",
    //     help = "Filepath to keypair to use",
    // )]
    // keypair: String,
    #[arg(
        long,
        value_name = "USERNAME",
        global = true,
        help = "Username used to connect to the server"
    )]
    username: Option<String>,
    #[command(subcommand)]
    command: Commands
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(about = "Connect to pool and start mining.")]
    Mine(MineArgs),
    #[command(about = "Transfer sol to the pool authority to sign up.")]
    Signup,
}

// --------------------------------


#[tokio::main]
async fn main() {
    let args = Args::parse();

    let base_url = args.url;
    let mut username: String = args.username.unwrap_or("user".to_string());

    match get() {
        Ok(hostname) => {
            let hostname_str = hostname.to_string_lossy();

            // Check if the username contains "."
            if !username.contains('.') {
                // Append "." + hostname to username
                username = format!("{}.{}", username, hostname_str);
            }

            println!("Hostname: {}", hostname_str);
        },
        Err(e) => eprintln!("Failed to get hostname: {}", e),
    }

    match args.command {
        Commands::Mine(args) => {
            mine::mine(args, base_url , username).await;
        },
        Commands::Signup => {
            // signup(base_url, key).await;
        }
    }
}

