mod crypto;
mod mqtt_client;
mod device;
mod message;

use structopt::StructOpt;
use std::sync::{Arc, Mutex};
use std::io::{self, BufRead, Write};
use std::thread;
use std::time::Duration;
use colored::*;

#[derive(Debug, StructOpt)]
#[structopt(name = "secure-messenger", about = "A secure messaging CLI tool with post-quantum encryption")]
enum Cli {
    #[structopt(name = "start", about = "Start the messenger client")]
    Start {
        #[structopt(short, long, default_value = "localhost")]
        broker: String,
        
        #[structopt(short, long, default_value = "1883")]
        port: u16,
        
        #[structopt(short, long, help = "Your display name")]
        name: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Cli::from_args();
    
    match opt {
        Cli::Start { broker, port, name } => start_messenger(&broker, port, &name)?,
    }
    
    Ok(())
}

fn start_messenger(broker: &str, port: u16, display_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "Secure Messenger CLI".green().bold());
    println!("Connecting to MQTT broker at {}:{} as {}", broker, port, display_name);
    
    // Initialize crypto context
    let crypto_context = Arc::new(crypto::CryptoContext::new());
    let device_id = crypto_context.device_id.clone();
    
    println!("Your device ID: {}", device_id.cyan());
    println!("Initializing secure connection...");
    
    // Create MQTT messenger
    let messenger = mqtt_client::MqttMessenger::new(
        broker,
        port,
        display_name,
        Arc::clone(&crypto_context),
    )?;
    
    // Wrap messenger in Arc<Mutex<>> for thread-safe sharing
    let messenger_arc = Arc::new(Mutex::new(messenger));
    
    // Set up message callback
    {
        let mut messenger = messenger_arc.lock().unwrap();
        messenger.set_message_callback(|sender, message| {
            println!("\n{}: {}", sender.yellow(), message);
            print!("{}", "> ".green());
            io::stdout().flush().unwrap();
        });
        
        // Announce presence
        messenger.announce_presence()?;
    }
    
    println!("Device announced on network");
    
    // Start a background thread to periodically announce presence
    let messenger_clone = Arc::clone(&messenger_arc);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(60));
            if let Ok(mut messenger) = messenger_clone.lock() {
                if let Err(e) = messenger.announce_presence() {
                    eprintln!("Failed to announce presence: {}", e);
                }
            }
        }
    });
    
    // CLI input loop
    println!("{}", "\nAvailable commands:".cyan());
    println!("  {} - Show connected devices", "devices".cyan());
    println!("  {} [device_id] [message] - Send direct message", "send".cyan());
    println!("  {} [message] - Broadcast to all devices", "broadcast".cyan());
    println!("  {} [device_id] - Initialize secure session", "connect".cyan());
    println!("  {} - Exit the application", "exit".cyan());
    println!("");
    
    let stdin = io::stdin();
    loop {
        print!("{}", "> ".green());
        io::stdout().flush()?;
        
        let mut input = String::new();
        stdin.lock().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        let parts: Vec<&str> = input.splitn(3, ' ').collect();
        let command = parts[0].to_lowercase();
        
        match command.as_str() {
            "exit" => {
                println!("Exiting...");
                break;
            },
            "devices" => {
                let devices = {
                    let messenger = messenger_arc.lock().unwrap();
                    messenger.get_known_devices()
                };
                
                println!("\n{} known devices:", devices.len());
                for device in devices {
                    println!("  {} ({}): {}", 
                        device.display_name.yellow(), 
                        device.device_id.cyan(),
                        if device.device_id == device_id { "This device".green() } else { "Online".normal() }
                    );
                }
                println!("");
            },
            "send" => {
                if parts.len() < 3 {
                    println!("Usage: send [device_id] [message]");
                    continue;
                }
                
                let recipient_id = parts[1];
                let message = parts[2];
                
                let result = {
                    let mut messenger = messenger_arc.lock().unwrap();
                    messenger.send_text_message(Some(recipient_id.to_string()), message)
                };
                
                match result {
                    Ok(_) => println!("Message sent to {}", recipient_id.cyan()),
                    Err(e) => println!("Failed to send message: {}", e.red()),
                }
            },
            "broadcast" => {
                if parts.len() < 2 {
                    println!("Usage: broadcast [message]");
                    continue;
                }
                
                let message = if parts.len() == 2 { parts[1] } else { &input[10..] };
                
                let result = {
                    let mut messenger = messenger_arc.lock().unwrap();
                    messenger.send_text_message(None, message)
                };
                
                match result {
                    Ok(_) => println!("Broadcast message sent"),
                    Err(e) => println!("Failed to broadcast message: {}", e.red()),
                }
            },
            "connect" => {
                if parts.len() < 2 {
                    println!("Usage: connect [device_id]");
                    continue;
                }
                
                let recipient_id = parts[1];
                
                let result = {
                    let mut messenger = messenger_arc.lock().unwrap();
                    messenger.initialize_session(recipient_id)
                };
                
                match result {
                    Ok(_) => println!("Secure session established with {}", recipient_id.cyan()),
                    Err(e) => println!("Failed to establish session: {}", e.red()),
                }
            },
            _ => {
                println!("Unknown command: {}", command.red());
            }
        }
    }
    
    Ok(())
}