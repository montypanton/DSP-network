// Chat mode function for continuous conversation
fn enter_chat_mode(messenger_arc: Arc<Mutex<mqtt_client::MqttMessenger>>, recipient_id: &str, recipient_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let is_chat_mode = Arc::new(AtomicBool::new(true));
    
    // Clone for the interrupt handler
    let is_chat_mode_clone = Arc::clone(&is_chat_mode);
    
    // Try to initialize the session first
    {
        let mut messenger = messenger_arc.lock().unwrap();
        messenger.initialize_session(recipient_id)?;
    }
    
    // Set up a special message callback for chat mode
    {
        let mut messenger = messenger_arc.lock().unwrap();
        let recipient_id_copy = recipient_id.to_string();
        messenger.set_message_callback(move |sender, message| {
            // Only show messages from our chat partner
            if sender.contains(&recipient_id_copy) || sender == recipient_name {
                println!("\r\x1B[K{}: {}", sender.yellow(), message);
            }
            print!("\r[Chat with {}]> ", recipient_name.yellow());
            io::stdout().flush().unwrap();
        });
    }
    
    println!("\n{}", "Entering chat mode".cyan());
    println!("You are now chatting with {}. Type /exit to leave chat mode.", recipient_name.yellow());
    
    // Ctrl+C handler to exit chat mode
    ctrlc::set_handler(move || {
        is_chat_mode_clone.store(false, Ordering::SeqCst);
        println!("\nExiting chat mode...");
    }).expect("Error setting Ctrl-C handler");
    
    // Chat input loop
    let stdin = io::stdin();
    while is_chat_mode.load(Ordering::SeqCst) {
        print!("\r[Chat with {}]> ", recipient_name.yellow());
        io::stdout().flush()?;
        
        let mut input = String::new();
        stdin.lock().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        if input == "/exit" {
            println!("Exiting chat mode...");
            break;
        }
        
        // Send the message
        let result = {
            let mut messenger = messenger_arc.lock().unwrap();
            messenger.send_text_message(Some(recipient_id.to_string()), input)
        };
        
        match result {
            Ok(_) => {
                // Just print the message we sent with our name
                if let Ok(messenger) = messenger_arc.lock() {
                    println!("\r\x1B[K{}: {}", messenger.display_name.green(), input);
                }
            },
            Err(e) => println!("Failed to send message: {}", e.to_string().red()),
        }
    }
    
    // Restore the original message callback
    {
        let mut messenger = messenger_arc.lock().unwrap();
        messenger.set_message_callback(|sender, message| {
            println!("\n{}: {}", sender.yellow(), message);
            print!("{}", "> ".green());
            io::stdout().flush().unwrap();
        });
    }
    
    println!("\nReturned to command mode.");
    
    Ok(())
}mod crypto;
mod mqtt_client;
mod device;
mod message;

use structopt::StructOpt;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::io::{self, BufRead, Write};
use std::thread;
use std::time::Duration;
use colored::Colorize;
use ctrlc;

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
    let mut crypto_context = Arc::new(crypto::CryptoContext::new());
    
    // Configure key rotation - every 5 messages or 5 minutes
    {
        let crypto_context_mut = Arc::get_mut(&mut crypto_context).unwrap();
        crypto_context_mut.configure_rotation(5, 300);
    }
    
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
    
    // Wait a moment to allow discovery to complete
    thread::sleep(Duration::from_secs(1));
    
    // Start a background thread to periodically announce presence
    let messenger_clone = Arc::clone(&messenger_arc);
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(30));
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
    println!("  {} [device_id] - Start chat session with a device", "chat".cyan());
    println!("  {} - Show this help message", "help".cyan());
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
                    let devices = messenger.get_known_devices();
                    devices
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
                
                // First try to establish a secure session
                {
                    let mut messenger = messenger_arc.lock().unwrap();
                    let _ = messenger.initialize_session(recipient_id);
                }
                
                // Small delay to allow session setup
                thread::sleep(Duration::from_millis(100));
                
                // Then send the message
                let result = {
                    let mut messenger = messenger_arc.lock().unwrap();
                    messenger.send_text_message(Some(recipient_id.to_string()), message)
                };
                
                match result {
                    Ok(_) => println!("Message sent to {}", recipient_id.cyan()),
                    Err(e) => println!("Failed to send message: {}", e.to_string().red()),
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
                    Err(e) => println!("Failed to broadcast message: {}", e.to_string().red()),
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
                    Err(e) => println!("Failed to establish session: {}", e.to_string().red()),
                }
            },
            "chat" => {
                if parts.len() < 2 {
                    println!("Usage: chat [device_id]");
                    continue;
                }
                
                let recipient_id = parts[1];
                
                // Get the recipient's name if available
                let recipient_name = {
                    let messenger = messenger_arc.lock().unwrap();
                    let devices = messenger.get_known_devices();
                    let device = devices.iter().find(|d| d.device_id == recipient_id);
                    
                    match device {
                        Some(d) => d.display_name.clone(),
                        None => recipient_id.to_string()
                    }
                };
                
                if let Err(e) = enter_chat_mode(Arc::clone(&messenger_arc), recipient_id, &recipient_name) {
                    println!("Chat mode error: {}", e.to_string().red());
                }
            },
            "help" => {
                println!("{}", "\nAvailable commands:".cyan());
                println!("  {} - Show connected devices", "devices".cyan());
                println!("  {} [device_id] [message] - Send direct message", "send".cyan());
                println!("  {} [message] - Broadcast to all devices", "broadcast".cyan());
                println!("  {} [device_id] - Initialize secure session", "connect".cyan());
                println!("  {} [device_id] - Start chat session with a device", "chat".cyan());
                println!("  {} - Show this help message", "help".cyan());
                println!("  {} - Exit the application", "exit".cyan());
                println!("");
            },
            _ => {
                println!("Unknown command: {}", command.red());
                println!("Type 'help' to see available commands");
            }
        }
    }
    
    Ok(())
}