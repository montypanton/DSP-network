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
// Add missing imports
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use rand::{rngs::OsRng, RngCore};

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
            
            loop {
                match connection.recv() {
                    Ok(notification) => {
                        if let Ok(Event::Incoming(Packet::Publish(publish))) = notification {
                            // Process received message
                            if let Ok(enc_message) = serde_json::from_slice::<EncryptedMessage>(&publish.payload) {
                                Self::process_message(
                                    &thread_crypto,
                                    &enc_message,
                                    &thread_devices,
                                    &thread_callback,
                                    &thread_device_id,
                                );
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Connection error: {:?}", e);
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
                        }
                    }
                }
            },
            MessageType::TextMessage => {
                // Process text message
                // For encrypted messages, we need to decrypt them first
                if let Ok(ct_bytes) = BASE64.decode(&enc_message.encrypted_data) {
                    if let Ok(nonce) = BASE64.decode(&enc_message.nonce) {
                        // Handle forward secrecy
                        if let Some(ephemeral_key) = &enc_message.ephemeral_public {
                            if let Ok(key_bytes) = BASE64.decode(ephemeral_key) {
                                let _ = crypto.handle_ephemeral_key(&enc_message.sender_id, &key_bytes);
                            }
                        }
                        
                        // Updated decryption logic
                        let decryption_result = if let Some(_) = &enc_message.recipient_id {
                            // Check if this is an initial Kyber message before a session is established
                            if enc_message.is_initial_kyber && ct_bytes.len() >= 1088 {
                                crypto.decrypt_message(&ct_bytes[..1088], &nonce, &ct_bytes[1088..])
                            } else {
                                // Try session-based decryption first
                                match crypto.decrypt_with_session(&enc_message.sender_id, &ct_bytes) {
                                    Ok(plaintext) => Ok(plaintext),
                                    Err(_) if ct_bytes.len() >= 1088 => {
                                        // If session decryption fails and the ciphertext is large enough,
                                        // try Kyber decryption as a fallback
                                        crypto.decrypt_message(&ct_bytes[..1088], &nonce, &ct_bytes[1088..])
                                    },
                                    Err(e) => Err(e)
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
                        
                        if let Ok(decrypted) = decryption_result {
                            if let Ok(text_msg) = serde_json::from_slice::<TextMessage>(&decrypted) {
                                // Call the callback with the decrypted message
                                if let Some(cb) = &*callback.lock().unwrap() {
                                    cb(text_msg.from_name, text_msg.content);
                                }
                            }
                        }
                    }
                }
            },
            MessageType::KeyExchange => {
                // Process key exchange message
                if let Some(ephemeral_key) = &enc_message.ephemeral_public {
                    if let Ok(key_bytes) = BASE64.decode(ephemeral_key) {
                        let _ = crypto.handle_ephemeral_key(&enc_message.sender_id, &key_bytes);
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
        
        Ok(())
    }
    
    // Initialize a forward secrecy session with another device
    pub fn initialize_session(&mut self, recipient_id: &str) -> Result<(), String> {
        // Find the recipient's device info
        let devices = self.known_devices.lock().unwrap();
        let _recipient = devices.iter().find(|d| d.device_id == recipient_id)
            .ok_or_else(|| format!("Device {} not found", recipient_id))?;
            
        // Generate an ephemeral keypair
        let (_, public) = self.crypto.generate_ephemeral_keypair();
        
        // Create a key exchange message
        let message = EncryptedMessage {
            sender_id: self.device_id.clone(),
            recipient_id: Some(recipient_id.to_string()),
            encrypted_data: "".to_string(), // No data needed for key exchange
            nonce: "".to_string(),
            message_type: MessageType::KeyExchange,
            timestamp: Utc::now().timestamp() as u64,
            ephemeral_public: Some(BASE64.encode(public.as_bytes())),
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
                devices.iter().find(|d| d.device_id == *recipient)
                    .ok_or_else(|| format!("Device {} not found", recipient))?
                    .clone()
            };
            
            // Try to use session keys
            let (encrypted, maybe_new_ephemeral) = match self.crypto.encrypt_with_session(recipient, text_msg_json.as_bytes()) {
                Ok((enc, eph)) => (enc, eph),
                Err(_) => {
                    // No session yet, try to establish one
                    self.initialize_session(recipient)?;
                    
                    // Fall back to Kyber encryption for this message
                    let (ciphertext, nonce_bytes) = self.crypto.encrypt_message(&recipient_info.public_key, text_msg_json.as_bytes())?;
                    
                    // Combine ciphertext and encrypted data
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&ciphertext);
                    
                    // Add encrypted data
                    let encrypted_data_nonce = Nonce::from_slice(&nonce_bytes);
                    
                    // Create a dummy AEAD key for the initial message
                    let mut aead_key_bytes = [0u8; 32];
                    OsRng.fill_bytes(&mut aead_key_bytes);
                    let aead_key = Key::from_slice(&aead_key_bytes);
                    let cipher = ChaCha20Poly1305::new(aead_key);
                    
                    if let Ok(encrypted) = cipher.encrypt(encrypted_data_nonce, text_msg_json.as_bytes()) {
                        combined.extend_from_slice(&encrypted);
                    } else {
                        // Fallback if encryption fails
                        combined.extend_from_slice(text_msg_json.as_bytes());
                    }
                    
                    (combined, None)
                }
            };
            
            // Set up the ephemeral key for the message if we have one
            let eph_key = maybe_new_ephemeral.map(|k| BASE64.encode(k.as_bytes()));
            
            // Get the first 12 bytes as nonce
            let nonce_bytes = if encrypted.len() >= 12 {
                encrypted[..12].to_vec()
            } else {
                vec![0u8; 12] // Should never happen
            };
            
            // Set the is_initial_kyber flag based on whether we used session keys
            let is_initial = maybe_new_ephemeral.is_none();
            
            (BASE64.encode(&encrypted), BASE64.encode(&nonce_bytes), eph_key, format!("secure-msg/device/{}", recipient), is_initial)
        } else {
            // Broadcast message - use Kyber for each known device (simplified to just basic encryption here)
            // Use PQPublicKey trait to access as_bytes
            let kyber_pk_bytes = self.crypto.kyber_public_key.as_bytes();
            let (ciphertext, nonce_bytes) = self.crypto.encrypt_message(&BASE64.encode(kyber_pk_bytes), text_msg_json.as_bytes())?;
            
            // In reality, you'd encrypt differently for each recipient in a broadcast
            (BASE64.encode(&ciphertext), BASE64.encode(&nonce_bytes), None, "secure-msg/broadcast".to_string(), false)
        };
        
        // Create the encrypted message envelope
        let message = EncryptedMessage {
            sender_id: self.device_id.clone(),
            recipient_id: recipient_id,
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