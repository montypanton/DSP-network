use crate::crypto::CryptoContext;
use crate::message::{DeviceInfo, EncryptedMessage, MessageType, TextMessage};
use rumqttc::{Client, MqttOptions, QoS, Event, Packet};
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json;
use chrono::Utc;
use pqcrypto_traits::kem::PublicKey as PQPublicKey;

#[derive(Clone)]
pub struct MqttMessenger {
    device_id: String,
    client: Arc<Mutex<Client>>,
    crypto: Arc<CryptoContext>,
    display_name: String,
    known_devices: Arc<Mutex<Vec<DeviceInfo>>>,
    message_callback: Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + 'static>>>>,
}

impl MqttMessenger {
    pub fn new(
        broker_url: &str,
        broker_port: u16,
        display_name: &str,
        crypto: Arc<CryptoContext>,
    ) -> Result<Self, String> {
        let device_id = crypto.device_id.clone();
        
        // Set up MQTT client
        let mut mqttopts = MqttOptions::new(
            format!("secure-msg-{}", device_id),
            broker_url,
            broker_port,
        );
        mqttopts.set_keep_alive(Duration::from_secs(30));
        
        let (client, mut connection) = Client::new(mqttopts, 10);
        let client = Arc::new(Mutex::new(client));
        
        // Clone what we need for the event loop thread
        let thread_crypto = Arc::clone(&crypto);
        let thread_device_id = device_id.clone();
        let known_devices = Arc::new(Mutex::new(Vec::new()));
        let thread_devices = Arc::clone(&known_devices);
        let message_callback = Arc::new(Mutex::new(None as Option<Box<dyn Fn(String, String) + Send + 'static>>));
        let thread_callback = Arc::clone(&message_callback);
        let thread_client = Arc::clone(&client);
        
        // Create the messenger instance
        let mut messenger = Self {
            device_id: device_id.clone(),
            client,
            crypto,
            display_name: display_name.to_string(),
            known_devices,
            message_callback,
        };
        
        // Start the event loop in a separate thread
        thread::spawn(move || {
            println!("Starting MQTT event loop...");
            
            // Initialize connection - make sure we're properly subscribed first
            if let Ok(mut client) = thread_client.lock() {
                // Subscribe to all topics
                let _ = client.subscribe(format!("secure-msg/device/{}", thread_device_id), QoS::AtLeastOnce);
                let _ = client.subscribe("secure-msg/broadcast", QoS::AtLeastOnce);
                let _ = client.subscribe("secure-msg/discovery", QoS::AtLeastOnce);
                
                // Request device announcements when we first connect
                let discovery_request = EncryptedMessage {
                    sender_id: thread_device_id.clone(),
                    recipient_id: None,
                    encrypted_data: BASE64.encode("discovery_request".as_bytes()),
                    nonce: BASE64.encode([0u8; 12]),
                    message_type: MessageType::DeviceAnnounce,
                    timestamp: Utc::now().timestamp() as u64,
                    ephemeral_public: None,
                    is_initial_kyber: false,
                };
                
                if let Ok(json) = serde_json::to_string(&discovery_request) {
                    let _ = client.publish(
                        "secure-msg/discovery",
                        QoS::AtLeastOnce,
                        false,
                        json.as_bytes(),
                    );
                }
            }
            
            loop {
                // Handle the double Result wrapper from connection.recv()
                match connection.recv() {
                    Ok(Ok(Event::Incoming(Packet::Publish(publish)))) => {
                        // Process received message
                        if let Ok(enc_message) = serde_json::from_slice::<EncryptedMessage>(&publish.payload) {
                            // Debug log
                            println!("Message received from {} (type: {:?})", 
                                    enc_message.sender_id, 
                                    enc_message.message_type);
                            
                            // If this is a discovery request, respond with our device info
                            let topic = publish.topic.clone();
                            if topic == "secure-msg/discovery" 
                               && enc_message.message_type == MessageType::DeviceAnnounce 
                               && enc_message.sender_id != thread_device_id {
                                
                                // If this is a discovery request or another device's announcement,
                                // respond with our own device info only if it's a discovery request
                                if let Ok(mut client) = thread_client.lock() {
                                    // Only respond to actual discovery requests, not just announcements
                                    let is_discovery_request = if let Ok(decoded) = BASE64.decode(&enc_message.encrypted_data) {
                                        String::from_utf8_lossy(&decoded) == "discovery_request"
                                    } else {
                                        false
                                    };
                                    
                                    if is_discovery_request {
                                        let device_info = thread_crypto.get_device_info(&thread_device_id);
                                        if let Ok(device_json) = serde_json::to_string(&device_info) {
                                            let response = EncryptedMessage {
                                                sender_id: thread_device_id.clone(),
                                                recipient_id: None,
                                                encrypted_data: BASE64.encode(device_json.as_bytes()),
                                                nonce: BASE64.encode([0u8; 12]),
                                                message_type: MessageType::DeviceAnnounce,
                                                timestamp: Utc::now().timestamp() as u64,
                                                ephemeral_public: None,
                                                is_initial_kyber: false,
                                            };
                                            
                                            if let Ok(json) = serde_json::to_string(&response) {
                                                let _ = client.publish(
                                                    "secure-msg/discovery",
                                                    QoS::AtLeastOnce,
                                                    false,
                                                    json.as_bytes(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            
                            Self::process_message(
                                &*thread_crypto,
                                &enc_message,
                                &thread_devices,
                                &thread_callback,
                                &thread_device_id,
                            );
                        }
                    },
                    Ok(Ok(_)) => {
                        // Handle other event types if needed
                    },
                    Ok(Err(conn_err)) => {
                        eprintln!("Connection error: {:?}", conn_err);
                        // Try to reconnect after a delay
                        thread::sleep(Duration::from_secs(5));
                    },
                    Err(recv_err) => {
                        eprintln!("Receive error: {:?}", recv_err);
                        // Try to reconnect after a delay
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
        });
        
        // Subscribe to relevant topics
        messenger.subscribe_to_topics()?;
        
        Ok(messenger)
    }
    
    // Process a received message
    fn process_message(
        crypto: &CryptoContext,
        enc_message: &EncryptedMessage,
        known_devices: &Arc<Mutex<Vec<DeviceInfo>>>,
        callback: &Arc<Mutex<Option<Box<dyn Fn(String, String) + Send + 'static>>>>,
        device_id: &str,
    ) {
        // Skip messages from ourselves
        if enc_message.sender_id == *device_id {
            return;
        }
        
        // Check if message is for us (or broadcast)
        if let Some(recipient) = &enc_message.recipient_id {
            if recipient != device_id {
                return;
            }
        }
        
        println!("Processing message type: {:?} from {}", enc_message.message_type, enc_message.sender_id);
        
        match enc_message.message_type {
            MessageType::DeviceAnnounce => {
                // Process device announce message
                if let Ok(device_info_bytes) = BASE64.decode(&enc_message.encrypted_data) {
                    if let Ok(device_info) = serde_json::from_slice::<DeviceInfo>(&device_info_bytes) {
                        let mut devices = known_devices.lock().unwrap();
                        
                        // Update device info if exists, otherwise add
                        let existing_idx = devices.iter().position(|d| d.device_id == device_info.device_id);
                        if let Some(idx) = existing_idx {
                            devices[idx] = device_info;
                        } else {
                            devices.push(device_info);
                            println!("New device added to known devices list");
                        }
                    }
                }
            },
            MessageType::TextMessage => {
                // Process text message
                // For encrypted messages, we need to decrypt them first
                println!("Received text message, attempting decryption");
                
                if let Ok(ct_bytes) = BASE64.decode(&enc_message.encrypted_data) {
                    if let Ok(nonce) = BASE64.decode(&enc_message.nonce) {
                        // Handle forward secrecy
                        if let Some(ephemeral_key) = &enc_message.ephemeral_public {
                            if let Ok(key_bytes) = BASE64.decode(ephemeral_key) {
                                let _ = crypto.handle_ephemeral_key(&enc_message.sender_id, &key_bytes);
                            }
                        }
                        
                        // Decryption approaches
                        let decryption_result = if enc_message.is_initial_kyber && ct_bytes.len() >= 1088 {
                            // This is an initial Kyber message
                            println!("Attempting Kyber decryption");
                            crypto.decrypt_message(&ct_bytes[..1088], &nonce, &ct_bytes[1088..])
                        } else if let Some(_) = &enc_message.recipient_id {
                            // Try session-based decryption first for direct messages
                            println!("Attempting session decryption");
                            match crypto.decrypt_with_session(&enc_message.sender_id, &ct_bytes) {
                                Ok(plaintext) => Ok(plaintext),
                                Err(e) => {
                                    println!("Session decryption failed: {}, trying Kyber fallback", e);
                                    if ct_bytes.len() >= 1088 {
                                        crypto.decrypt_message(&ct_bytes[..1088], &nonce, &ct_bytes[1088..])
                                    } else {
                                        Err(format!("Cannot decrypt: ciphertext too small"))
                                    }
                                }
                            }
                        } else {
                            // Broadcast message - decrypt with Kyber
                            if ct_bytes.len() >= 1088 {
                                crypto.decrypt_message(&ct_bytes[..1088], &nonce, &ct_bytes[1088..])
                            } else {
                                Err(format!("Broadcast ciphertext too small: {} bytes", ct_bytes.len()))
                            }
                        };
                        
                        match decryption_result {
                            Ok(decrypted) => {
                                match serde_json::from_slice::<TextMessage>(&decrypted) {
                                    Ok(text_msg) => {
                                        println!("Successfully decrypted message from {}", text_msg.from_name);
                                        // Call the callback with the decrypted message
                                        if let Some(cb) = &*callback.lock().unwrap() {
                                            cb(text_msg.from_name, text_msg.content);
                                        }
                                    },
                                    Err(e) => println!("Failed to parse decrypted message: {}", e)
                                }
                            },
                            Err(e) => println!("Failed to decrypt message: {}", e)
                        }
                    }
                }
            },
            MessageType::KeyExchange => {
                // Process key exchange message
                println!("Received key exchange message");
                if let Some(ephemeral_key) = &enc_message.ephemeral_public {
                    if let Ok(key_bytes) = BASE64.decode(ephemeral_key) {
                        match crypto.handle_ephemeral_key(&enc_message.sender_id, &key_bytes) {
                            Ok(_) => println!("Established forward secrecy session with {}", enc_message.sender_id),
                            Err(e) => println!("Failed to establish session: {}", e)
                        }
                    }
                }
            }
        }
    }
    
    // Subscribe to necessary topics
    fn subscribe_to_topics(&mut self) -> Result<(), String> {
        let mut client = self.client.lock().unwrap();
        
        // Personal topic for direct messages
        let personal_topic = format!("secure-msg/device/{}", self.device_id);
        client.subscribe(personal_topic, QoS::AtLeastOnce).map_err(|e| format!("Subscription error: {:?}", e))?;
        
        // Broadcast topic
        client.subscribe("secure-msg/broadcast", QoS::AtLeastOnce).map_err(|e| format!("Subscription error: {:?}", e))?;
        
        // Discovery topic
        client.subscribe("secure-msg/discovery", QoS::AtLeastOnce).map_err(|e| format!("Subscription error: {:?}", e))?;
        
        Ok(())
    }
    
    // Set message callback
    pub fn set_message_callback<F>(&self, callback: F)
    where
        F: Fn(String, String) + Send + 'static,
    {
        let mut cb = self.message_callback.lock().unwrap();
        *cb = Some(Box::new(callback));
    }
    
    // Announce this device to the network
    pub fn announce_presence(&mut self) -> Result<(), String> {
        // Create device info message
        let device_info = self.crypto.get_device_info(&self.display_name);
        let device_info_json = serde_json::to_string(&device_info).map_err(|e| format!("JSON error: {}", e))?;
        
        // Create encrypted message (not actually encrypted for discovery)
        let message = EncryptedMessage {
            sender_id: self.device_id.clone(),
            recipient_id: None, // Broadcast
            encrypted_data: BASE64.encode(device_info_json.as_bytes()),
            nonce: BASE64.encode([0u8; 12]), // Dummy nonce
            message_type: MessageType::DeviceAnnounce,
            timestamp: Utc::now().timestamp() as u64,
            ephemeral_public: None,
            is_initial_kyber: false,
        };
        
        let message_json = serde_json::to_string(&message).map_err(|e| format!("JSON error: {}", e))?;
        
        // Publish to discovery topic
        let mut client = self.client.lock().unwrap();
        client.publish(
            "secure-msg/discovery",
            QoS::AtLeastOnce,
            false,
            message_json.as_bytes(),
        ).map_err(|e| format!("Publish error: {:?}", e))?;
        
        // Also add ourselves to the known devices list
        let mut devices = self.known_devices.lock().unwrap();
        if !devices.iter().any(|d| d.device_id == self.device_id) {
            devices.push(device_info);
        }
        
        Ok(())
    }
    
    // Initialize a forward secrecy session with another device
    pub fn initialize_session(&mut self, recipient_id: &str) -> Result<(), String> {
        // Find the recipient's device info
        let devices = self.known_devices.lock().unwrap();
        let recipient = devices.iter().find(|d| d.device_id == recipient_id)
            .ok_or_else(|| format!("Device {} not found", recipient_id))?
            .clone();
        
        // Drop the lock before proceeding with potentially time-consuming operations
        drop(devices);
            
        // Generate an ephemeral keypair
        let (_, public) = self.crypto.generate_ephemeral_keypair();
        let ephemeral_key_b64 = BASE64.encode(public.as_bytes());
        
        // Create a key exchange message
        let message = EncryptedMessage {
            sender_id: self.device_id.clone(),
            recipient_id: Some(recipient_id.to_string()),
            encrypted_data: "".to_string(), // No data needed for key exchange
            nonce: "".to_string(),
            message_type: MessageType::KeyExchange,
            timestamp: Utc::now().timestamp() as u64,
            ephemeral_public: Some(ephemeral_key_b64),
            is_initial_kyber: false,
        };
        
        let message_json = serde_json::to_string(&message).map_err(|e| format!("JSON error: {}", e))?;
        
        // Send the key exchange message
        let recipient_topic = format!("secure-msg/device/{}", recipient_id);
        let mut client = self.client.lock().unwrap();
        client.publish(
            recipient_topic,
            QoS::AtLeastOnce,
            false,
            message_json.as_bytes(),
        ).map_err(|e| format!("Publish error: {:?}", e))?;
        
        // Also create a client-side session
        if let Some(ephemeral_key) = recipient.ephemeral_key {
            // If the recipient has already shared their ephemeral key, use it
            let ephemeral_bytes = BASE64.decode(&ephemeral_key)
                .map_err(|_| "Invalid ephemeral key encoding".to_string())?;
            
            // Create a session on our side too
            self.crypto.handle_ephemeral_key(recipient_id, &ephemeral_bytes)?;
        }
        
        Ok(())
    }
    
    // Send a text message to another device
    pub fn send_text_message(&mut self, recipient_id: Option<String>, content: &str) -> Result<(), String> {
        // Create the text message
        let text_msg = TextMessage {
            content: content.to_string(),
            from_name: self.display_name.clone(),
            timestamp: Utc::now().timestamp() as u64,
        };
        
        let text_msg_json = serde_json::to_string(&text_msg).map_err(|e| format!("JSON error: {}", e))?;
        
        let (encrypted_data, nonce, ephemeral_public, topic, is_initial_kyber) = if let Some(recipient) = &recipient_id {
            // Personal message - use forward secrecy if available
            let recipient_info = {
                let devices = self.known_devices.lock().unwrap();
                let device = devices.iter().find(|d| d.device_id == *recipient);
                
                match device {
                    Some(d) => d.clone(),
                    None => return Err(format!("Device {} not found", recipient))
                }
            };
            
            // Try to use session keys first
            let encryption_result = self.crypto.encrypt_with_session(recipient, text_msg_json.as_bytes());
            
            match encryption_result {
                Ok((enc, eph)) => {
                    // Successfully encrypted with session keys
                    // Get the first 12 bytes as nonce (if available)
                    let nonce_bytes = if enc.len() >= 12 {
                        enc[..12].to_vec()
                    } else {
                        vec![0u8; 12]
                    };
                    
                    println!("Encrypted message with session keys for {}", recipient);
                    
                    // Set up the ephemeral key for the message if we have one
                    let eph_key = eph.map(|k| BASE64.encode(k.as_bytes()));
                    
                    (BASE64.encode(&enc), BASE64.encode(&nonce_bytes), eph_key, 
                     format!("secure-msg/device/{}", recipient), false)
                },
                Err(e) => {
                    println!("Session encryption failed: {}, falling back to Kyber", e);
                    
                    // No session yet, fall back to Kyber encryption
                    let (ciphertext, nonce_bytes) = self.crypto.encrypt_message(&recipient_info.public_key, text_msg_json.as_bytes())?;
                    
                    (BASE64.encode(&ciphertext), BASE64.encode(&nonce_bytes), None, 
                     format!("secure-msg/device/{}", recipient), true)
                }
            }
        } else {
            // Broadcast message - use Kyber with our own public key
            println!("Preparing broadcast message");
            
            // Get encoded version of our Kyber public key
            let kyber_pk_bytes = self.crypto.kyber_public_key.as_bytes();
            let encoded_pk = BASE64.encode(kyber_pk_bytes);
            
            // Use our own public key just to create a valid encryption (this is a simplification)
            let (ciphertext, nonce_bytes) = self.crypto.encrypt_message(&encoded_pk, text_msg_json.as_bytes())?;
            
            (BASE64.encode(&ciphertext), BASE64.encode(&nonce_bytes), None, 
             "secure-msg/broadcast".to_string(), true)
        };
        
        // Create the encrypted message envelope
        let message = EncryptedMessage {
            sender_id: self.device_id.clone(),
            recipient_id,
            encrypted_data,
            nonce,
            message_type: MessageType::TextMessage,
            timestamp: Utc::now().timestamp() as u64,
            ephemeral_public,
            is_initial_kyber,
        };
        
        let message_json = serde_json::to_string(&message).map_err(|e| format!("JSON error: {}", e))?;
        
        // Send the message
        let mut client = self.client.lock().unwrap();
        client.publish(
            topic,
            QoS::AtLeastOnce,
            false,
            message_json.as_bytes(),
        ).map_err(|e| format!("Publish error: {:?}", e))?;
        
        Ok(())
    }
    
    // Get list of known devices
    pub fn get_known_devices(&self) -> Vec<DeviceInfo> {
        self.known_devices.lock().unwrap().clone()
    }
}