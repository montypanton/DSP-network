use pqcrypto_kyber::kyber768::{self, PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as PQPublicKey, SharedSecret as _, Ciphertext as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::message::{DeviceInfo, SessionKeys};

// The crypto context for a device
pub struct CryptoContext {
    pub device_id: String,
    pub kyber_secret_key: SecretKey,
    pub kyber_public_key: PublicKey,
    pub session_keys: Arc<Mutex<HashMap<String, SessionKeys>>>,
    // New fields for key rotation tracking
    pub messages_since_rotation: Arc<Mutex<HashMap<String, usize>>>,
    pub rotation_interval: usize, // Number of messages before key rotation
    pub last_rotation_time: Arc<Mutex<HashMap<String, u64>>>, // Timestamp of last rotation
    pub time_rotation_interval: u64, // Seconds between time-based rotations
}

impl CryptoContext {
    pub fn new() -> Self {
        // Generate a new Kyber keypair
        let (kyber_public_key, kyber_secret_key) = kyber768::keypair();
        
        // Generate a unique device ID
        let mut device_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut device_id_bytes);
        let device_id = hex::encode(device_id_bytes);
        
        Self {
            device_id,
            kyber_secret_key,
            kyber_public_key,
            session_keys: Arc::new(Mutex::new(HashMap::new())),
            messages_since_rotation: Arc::new(Mutex::new(HashMap::new())),
            rotation_interval: 10, // Rotate keys every 10 messages by default
            last_rotation_time: Arc::new(Mutex::new(HashMap::new())),
            time_rotation_interval: 300, // Rotate keys every 5 minutes by default
        }
    }
    
    // Method to configure key rotation settings
    pub fn configure_rotation(&mut self, message_interval: usize, time_interval_secs: u64) {
        self.rotation_interval = message_interval;
        self.time_rotation_interval = time_interval_secs;
    }
    
    // Create a device info object for sharing
    pub fn get_device_info(&self, display_name: &str) -> DeviceInfo {
        // Generate an ephemeral key for this device to enable session establishment
        let (_, ephemeral_public) = self.generate_ephemeral_keypair();
        
        DeviceInfo {
            device_id: self.device_id.clone(),
            public_key: BASE64.encode(self.kyber_public_key.as_bytes()),
            display_name: display_name.to_string(),
            ephemeral_key: Some(BASE64.encode(ephemeral_public.as_bytes())),
        }
    }
    
    // Generate a new X25519 ephemeral keypair
    pub fn generate_ephemeral_keypair(&self) -> (EphemeralSecret, X25519Public) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        (secret, public)
    }
    
    // Encrypt a message for a recipient using Kyber for key exchange and ChaCha20-Poly1305 for encryption
    pub fn encrypt_message(&self, recipient_public_key_b64: &str, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        // Decode the recipient's public key
        let recipient_public_key_bytes = BASE64.decode(recipient_public_key_b64)
            .map_err(|_| "Invalid public key encoding".to_string())?;
        
        // Make sure we have the correct key size for Kyber768
        let expected_size = kyber768::public_key_bytes();
        if recipient_public_key_bytes.len() != expected_size {
            return Err(format!("Invalid public key size: {} bytes, expected {} bytes for Kyber768", 
                             recipient_public_key_bytes.len(), 
                             expected_size));
        }
        
        // Create the PublicKey directly from bytes
        let recipient_public_key = match PublicKey::from_bytes(&recipient_public_key_bytes) {
            Ok(pk) => pk,
            Err(_) => return Err("Invalid public key format".to_string()),
        };
        
        // Perform Kyber key encapsulation
        let (ciphertext, shared_secret) = kyber768::encapsulate(&recipient_public_key);
        
        // Use the shared secret to create a ChaCha20-Poly1305 key
        let aead_key = Key::from_slice(&shared_secret.as_bytes()[0..32]); // Ensure we use the right key size
        let cipher = ChaCha20Poly1305::new(aead_key);
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let encrypted_data = cipher.encrypt(nonce, message)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create the combined output
        let mut result = Vec::new();
        result.extend_from_slice(ciphertext.as_bytes());
        result.extend_from_slice(&encrypted_data);
        
        Ok((result, nonce_bytes.to_vec()))
    }
    
    // Decrypt a message using Kyber and ChaCha20-Poly1305
    pub fn decrypt_message(&self, ciphertext: &[u8], nonce: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        // Convert the ciphertext bytes to a Kyber ciphertext
        let kyber_ciphertext = match kyber768::Ciphertext::from_bytes(ciphertext) {
            Ok(ct) => ct,
            Err(_) => return Err("Invalid ciphertext format".to_string()),
        };
        
        if nonce.len() != 12 {
            return Err(format!("Invalid nonce size: {} bytes, expected 12", nonce.len()));
        }
        
        // Decapsulate the shared secret
        let shared_secret = kyber768::decapsulate(&kyber_ciphertext, &self.kyber_secret_key);
        
        // Create the ChaCha20-Poly1305 cipher
        let aead_key = Key::from_slice(&shared_secret.as_bytes()[0..32]);
        let cipher = ChaCha20Poly1305::new(aead_key);
        
        // Decrypt the message
        let nonce = Nonce::from_slice(nonce);
        cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
    
    // For forward secrecy: Create a new session key using X25519
    pub fn create_forward_secrecy_session(&self, recipient_id: &str, recipient_ephemeral_key: &[u8]) -> Result<X25519Public, String> {
        // Validate input size
        if recipient_ephemeral_key.len() != 32 {
            return Err(format!("Invalid ephemeral key size: {} bytes, expected 32", recipient_ephemeral_key.len()));
        }
        
        // Generate a new ephemeral keypair
        let (ephemeral_secret, ephemeral_public) = self.generate_ephemeral_keypair();
        
        // Convert the recipient's ephemeral key to an X25519 public key
        let recipient_pubkey_bytes: [u8; 32] = match recipient_ephemeral_key.try_into() {
            Ok(array) => array,
            Err(_) => return Err("Failed to convert ephemeral key bytes to array".to_string()),
        };
        
        let recipient_pubkey = X25519Public::from(recipient_pubkey_bytes);
        
        // Compute the shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);
        
        // Store or update the session
        let mut sessions = self.session_keys.lock().unwrap();
        
        if let Some(session) = sessions.get_mut(recipient_id) {
            // Store previous secret for possible out-of-order messages
            session.previous_secrets.push(session.shared_secret.clone());
            if session.previous_secrets.len() > 5 {
                // Keep only the 5 most recent previous secrets
                session.previous_secrets.remove(0);
            }
            
            // Update with new secret
            session.shared_secret = shared_secret.as_bytes().to_vec();
            println!("Updated existing session with {}", recipient_id);
        } else {
            // Create new session
            sessions.insert(recipient_id.to_string(), SessionKeys {
                recipient_id: recipient_id.to_string(),
                shared_secret: shared_secret.as_bytes().to_vec(),
                previous_secrets: Vec::new(),
            });
            println!("Created new session with {}", recipient_id);
        }
        
        // Reset rotation counters
        {
            let mut counters = self.messages_since_rotation.lock().unwrap();
            counters.insert(recipient_id.to_string(), 0);
        }
        
        {
            let mut times = self.last_rotation_time.lock().unwrap();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            times.insert(recipient_id.to_string(), now);
        }
        
        Ok(ephemeral_public)
    }
    
    // Check if key rotation is needed and perform if necessary
    pub fn check_key_rotation(&self, recipient_id: &str) -> Result<Option<X25519Public>, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let should_rotate_by_count;
        let should_rotate_by_time;
        
        // Check message count-based rotation
        {
            let mut counts = self.messages_since_rotation.lock().unwrap();
            let count = counts.entry(recipient_id.to_string()).or_insert(0);
            *count += 1;
            should_rotate_by_count = *count >= self.rotation_interval;
            
            if should_rotate_by_count {
                *count = 0; // Reset counter if we're going to rotate
            }
        }
        
        // Check time-based rotation
        {
            let mut last_times = self.last_rotation_time.lock().unwrap();
            let last_time = last_times.entry(recipient_id.to_string()).or_insert(now);
            should_rotate_by_time = now - *last_time >= self.time_rotation_interval;
            
            if should_rotate_by_time {
                *last_time = now; // Update last rotation time
            }
        }
        
        // If either condition is met, rotate keys
        if should_rotate_by_count || should_rotate_by_time {
            // First check if we have an active session
            let has_session = {
                let sessions = self.session_keys.lock().unwrap();
                sessions.contains_key(recipient_id)
            };
            
            if has_session {
                // Use the Device info to get their ephemeral key
                // This would normally go through DeviceManager but we'll simplify
                // by generating a new session directly
                return self.rotate_keys(recipient_id);
            }
        }
        
        Ok(None)
    }
    
    // Rotate keys for a session - simplified version that generates new key directly
    pub fn rotate_keys(&self, recipient_id: &str) -> Result<Option<X25519Public>, String> {
        // We'll need an active session to rotate
        let has_session = {
            let sessions = self.session_keys.lock().unwrap();
            sessions.contains_key(recipient_id)
        };
        
        if !has_session {
            return Err(format!("No active session with {}", recipient_id));
        }
        
        // Generate a new ephemeral keypair 
        let (ephemeral_secret, ephemeral_public) = self.generate_ephemeral_keypair();
        
        // Update the session counter
        {
            let mut counters = self.messages_since_rotation.lock().unwrap();
            counters.insert(recipient_id.to_string(), 0);
        }
        
        // Update rotation time
        {
            let mut times = self.last_rotation_time.lock().unwrap();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            times.insert(recipient_id.to_string(), now);
        }
        
        println!("Generated new key for rotation with {}", recipient_id);
        
        // Return the public key to be sent
        Ok(Some(ephemeral_public))
    }
    
    // Encrypt a message using the forward secrecy session
    pub fn encrypt_with_session(&self, recipient_id: &str, message: &[u8]) -> Result<(Vec<u8>, Option<X25519Public>), String> {
        let shared_secret;
        
        // Get the current session key
        {
            let sessions = self.session_keys.lock().unwrap();
            if let Some(session) = sessions.get(recipient_id) {
                shared_secret = session.shared_secret.clone();
            } else {
                return Err(format!("No session established with {}", recipient_id));
            }
        }
        
        // Use the shared secret to create a ChaCha20-Poly1305 key
        let aead_key = Key::from_slice(&shared_secret[0..32]);
        let cipher = ChaCha20Poly1305::new(aead_key);
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let encrypted_data = cipher.encrypt(nonce, message)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Check if we need to rotate keys and get new ephemeral public if so
        let new_ephemeral = match self.check_key_rotation(recipient_id) {
            Ok(maybe_public) => maybe_public,
            Err(e) => {
                println!("Warning: Key rotation check failed: {}", e);
                None
            }
        };
        
        // Combine nonce and encrypted data
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted_data);
        
        Ok((result, new_ephemeral))
    }
    
    // Decrypt a message using the forward secrecy session
    pub fn decrypt_with_session(&self, sender_id: &str, encrypted_package: &[u8]) -> Result<Vec<u8>, String> {
        if encrypted_package.len() < 12 {
            return Err(format!("Invalid encrypted package: {} bytes, expected at least 12", encrypted_package.len()));
        }
        
        // Split into nonce and ciphertext
        let nonce_bytes = &encrypted_package[0..12];
        let ciphertext = &encrypted_package[12..];
        
        // Try to decrypt with current and previous session keys
        let sessions = self.session_keys.lock().unwrap();
        
        if let Some(session) = sessions.get(sender_id) {
            // Try the current key first
            let aead_key = Key::from_slice(&session.shared_secret[0..32]);
            let cipher = ChaCha20Poly1305::new(aead_key);
            let nonce = Nonce::from_slice(nonce_bytes);
            
            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    return Ok(plaintext);
                },
                Err(_) => {
                    // Try previous keys
                    for (idx, prev_secret) in session.previous_secrets.iter().enumerate() {
                        let prev_key = Key::from_slice(&prev_secret[0..32]);
                        let prev_cipher = ChaCha20Poly1305::new(prev_key);
                        
                        if let Ok(plaintext) = prev_cipher.decrypt(nonce, ciphertext) {
                            println!("Decryption successful with previous key {}", idx);
                            return Ok(plaintext);
                        }
                    }
                    
                    return Err("Decryption failed with all available keys".to_string());
                }
            }
        } else {
            return Err(format!("No session established with {}", sender_id));
        }
    }
    
    // Handle an incoming ephemeral key for forward secrecy
    pub fn handle_ephemeral_key(&self, sender_id: &str, ephemeral_key: &[u8]) -> Result<(), String> {
        // Create a session with the new ephemeral key
        self.create_forward_secrecy_session(sender_id, ephemeral_key)?;
        Ok(())
    }
}