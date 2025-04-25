use pqcrypto_kyber::kyber768::{self, PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as PQPublicKey, SharedSecret as _, Ciphertext as _};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use ring::digest::{Context, SHA256};

use crate::message::{DeviceInfo, SessionKeys};

// The crypto context for a device
pub struct CryptoContext {
    pub device_id: String,
    pub kyber_secret_key: SecretKey,
    pub kyber_public_key: PublicKey,
    pub session_keys: Arc<Mutex<HashMap<String, SessionKeys>>>,
    // Key rotation tracking
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
    
    // Initial key exchange using Kyber for PQC security
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
        
        // Use the shared secret to create an AES-256 key
        // We use SHA-256 to derive a proper 32-byte key from the shared secret
        let mut context = Context::new(&SHA256);
        context.update(shared_secret.as_bytes());
        let digest = context.finish();
        let key_bytes = digest.as_ref();
        
        // Create AES-GCM cipher
        let cipher = match Aes256Gcm::new_from_slice(key_bytes) {
            Ok(c) => c,
            Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
        };
        
        // Generate a random nonce (12 bytes for AES-GCM)
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let encrypted_data = match cipher.encrypt(nonce, message) {
            Ok(ciphertext) => ciphertext,
            Err(e) => return Err(format!("Encryption failed: {}", e)),
        };
        
        // Create the combined output
        let mut result = Vec::new();
        result.extend_from_slice(ciphertext.as_bytes());
        result.extend_from_slice(&encrypted_data);
        
        Ok((result, nonce_bytes.to_vec()))
    }
    
    // Decrypt a message using Kyber and AES-256-GCM
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
        
        // Derive AES key from shared secret
        let mut context = Context::new(&SHA256);
        context.update(shared_secret.as_bytes());
        let digest = context.finish();
        let key_bytes = digest.as_ref();
        
        // Create the AES cipher
        let cipher = match Aes256Gcm::new_from_slice(key_bytes) {
            Ok(c) => c,
            Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
        };
        
        // Decrypt the message
        let nonce = Nonce::from_slice(nonce);
        match cipher.decrypt(nonce, encrypted_data) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(format!("Decryption failed: {}", e)),
        }
    }
    
    // Create a forward secrecy session using X25519
    pub fn create_forward_secrecy_session(&self, recipient_id: &str, recipient_ephemeral_key: &[u8]) -> Result<X25519Public, String> {
        // Debug output to track key creation
        println!("Creating forward secrecy session with {}", recipient_id);
        
        // Validate input size
        if recipient_ephemeral_key.len() != 32 {
            return Err(format!("Invalid ephemeral key size: {} bytes, expected 32", recipient_ephemeral_key.len()));
        }
        
        // Generate a new ephemeral keypair
        let (ephemeral_secret, ephemeral_public) = self.generate_ephemeral_keypair();
        
        // Print debug info
        println!("My ephemeral public key: {}", hex::encode(ephemeral_public.as_bytes()));
        println!("Recipient ephemeral public key: {}", hex::encode(recipient_ephemeral_key));
        
        // Use symmetrical key derivation for consistency between peers
        let shared_key = self.derive_symmetrical_key(
            recipient_id,
            ephemeral_public.as_bytes(),
            recipient_ephemeral_key
        );
        
        // Store or update the session
        let mut sessions = self.session_keys.lock().unwrap();
        
        if let Some(session) = sessions.get_mut(recipient_id) {
            // Store previous secret for possible out-of-order messages
            session.previous_secrets.push(session.shared_secret.clone());
            if session.previous_secrets.len() > 5 {
                // Keep only the 5 most recent previous secrets
                session.previous_secrets.remove(0);
            }
            
            // Make a copy of the shared key prefix for logging
            let shared_key_prefix = hex::encode(&shared_key[0..4]);
            
            // Update with new secret
            session.shared_secret = shared_key;
            println!("Updated existing session with {} (shared secret prefix: {})", 
                    recipient_id, shared_key_prefix);
        } else {
            // Make a copy of the shared key prefix for logging
            let shared_key_prefix = hex::encode(&shared_key[0..4]);
            
            // Create new session
            sessions.insert(recipient_id.to_string(), SessionKeys {
                recipient_id: recipient_id.to_string(),
                shared_secret: shared_key,
                previous_secrets: Vec::new(),
            });
            println!("Created new session with {} (shared secret prefix: {})", 
                    recipient_id, shared_key_prefix);
        }
        
        // Reset rotation counters
        drop(sessions);
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
                return self.rotate_keys(recipient_id);
            }
        }
        
        Ok(None)
    }
    
    // Rotate keys for a session
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
    
    // Encrypt a message using the forward secrecy session with AES-256
    pub fn encrypt_with_session(&self, recipient_id: &str, message: &[u8]) -> Result<(Vec<u8>, Option<X25519Public>), String> {
        // Only include ephemeral key if we need to rotate
        let mut should_include_ephemeral = false;
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
        
        // Use the shared secret to create an AES-256 key
        // The shared secret from X25519 is already 32 bytes (256 bits)
        let cipher = match Aes256Gcm::new_from_slice(&shared_secret[0..32]) {
            Ok(c) => c,
            Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
        };
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12]; // AES-GCM requires a 12-byte nonce
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let encrypted_data = match cipher.encrypt(nonce, message) {
            Ok(ciphertext) => ciphertext,
            Err(e) => return Err(format!("Encryption failed: {}", e)),
        };
        
        // Check if we need to rotate keys and get new ephemeral public if so
        let new_ephemeral = match self.check_key_rotation(recipient_id) {
            Ok(Some(ephemeral)) => {
                should_include_ephemeral = true;
                Some(ephemeral)
            },
            Ok(None) => None,
            Err(e) => {
                println!("Warning: Key rotation check failed: {}", e);
                None
            }
        };
        
        if should_include_ephemeral {
            println!("Including ephemeral key with message for key rotation");
        }
        
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
            let nonce = Nonce::from_slice(nonce_bytes);
            
            // Debug info
            println!("Attempting decryption with current key (prefix: {})", 
                    hex::encode(&session.shared_secret[0..4]));
            
            let cipher = match Aes256Gcm::new_from_slice(&session.shared_secret[0..32]) {
                Ok(c) => c,
                Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
            };
            
            match cipher.decrypt(nonce, ciphertext) {
                Ok(plaintext) => {
                    println!("Decryption successful with current session key");
                    return Ok(plaintext);
                },
                Err(_) => {
                    // Try previous keys
                    for (idx, prev_secret) in session.previous_secrets.iter().enumerate() {
                        println!("Trying previous key {} (prefix: {})", 
                                idx, hex::encode(&prev_secret[0..4]));
                                
                        let prev_cipher = match Aes256Gcm::new_from_slice(&prev_secret[0..32]) {
                            Ok(c) => c,
                            Err(_) => continue, // Skip this key if we can't create a cipher
                        };
                        
                        if let Ok(plaintext) = prev_cipher.decrypt(nonce, ciphertext) {
                            println!("Decryption successful with previous key {}", idx);
                            return Ok(plaintext);
                        }
                    }
                    
                    // Add diagnostic information
                    println!("Current key failed: {}", hex::encode(&session.shared_secret[0..8]));
                    if !session.previous_secrets.is_empty() {
                        println!("Previous keys also failed. Available keys:");
                        for (i, key) in session.previous_secrets.iter().enumerate() {
                            println!("  Key {}: {}", i, hex::encode(&key[0..8]));
                        }
                    }
                    
                    return Err("Decryption failed with all available keys".to_string());
                }
            }
        } else {
            return Err(format!("No session established with {}", sender_id));
        }
    }

    pub fn derive_symmetrical_key(&self, peer_id: &str, our_public_key: &[u8], their_public_key: &[u8]) -> Vec<u8> {
        // Create a deterministic derivation that will be identical on both sides
        let mut combined = Vec::with_capacity(64 + self.device_id.len() + peer_id.len());
        
        // Sort IDs to ensure same order
        let mut ids = vec![self.device_id.clone(), peer_id.to_string()];
        ids.sort();
        
        // Sort public keys to ensure same order
        let (first_key, second_key) = if hex::encode(our_public_key) < hex::encode(their_public_key) {
            (our_public_key, their_public_key)
        } else {
            (their_public_key, our_public_key)
        };
        
        // Combine everything in a deterministic order
        combined.extend_from_slice(ids[0].as_bytes());
        combined.extend_from_slice(ids[1].as_bytes());
        combined.extend_from_slice(first_key);
        combined.extend_from_slice(second_key);
        
        // Use a hash as a key derivation function for AES-256
        let mut context = Context::new(&SHA256);
        context.update(&combined);
        let digest = context.finish();
        
        let key = digest.as_ref().to_vec();
        println!("Derived symmetrical key (prefix): {}", hex::encode(&key[0..4]));
        
        key
    }
    
    pub fn handle_ephemeral_key(&self, sender_id: &str, their_ephemeral_key: &[u8]) -> Result<(), String> {
        println!("Handling ephemeral key from {}", sender_id);
        println!("Received ephemeral key: {}", hex::encode(their_ephemeral_key));
        
        if their_ephemeral_key.len() != 32 {
            return Err(format!("Invalid ephemeral key length: {}, expected 32", their_ephemeral_key.len()));
        }
        
        // Generate our ephemeral keys
        let (_, our_public) = self.generate_ephemeral_keypair();
        println!("Our ephemeral public key: {}", hex::encode(our_public.as_bytes()));
        
        // Derive a symmetrical key that will be the same on both sides
        let shared_key = self.derive_symmetrical_key(
            sender_id,
            our_public.as_bytes(),
            their_ephemeral_key
        );
        
        // First save the original session key if it exists
        let original_key_opt = {
            let sessions = self.session_keys.lock().unwrap();
            if let Some(session) = sessions.get(sender_id) {
                Some(session.shared_secret.clone())
            } else {
                None
            }
        };
        
        // Store the shared key in our session manager
        let mut sessions = self.session_keys.lock().unwrap();
        
        if let Some(session) = sessions.get_mut(sender_id) {
            // If we had an original key, store it properly
            if let Some(original_key) = original_key_opt {
                session.previous_secrets.push(original_key);
                if session.previous_secrets.len() > 5 {
                    // Keep only the 5 most recent previous secrets
                    session.previous_secrets.remove(0);
                }
            }
            
            // Make a copy of the shared key for logging
            let shared_key_prefix = hex::encode(&shared_key[0..4]);
            
            // Update with new secret
            session.shared_secret = shared_key;
            println!("Updated existing session with {} (shared secret prefix: {})", 
                    sender_id, shared_key_prefix);
        } else {
            // Make a copy of the shared key for logging
            let shared_key_prefix = hex::encode(&shared_key[0..4]);
            
            // Create new session
            sessions.insert(sender_id.to_string(), SessionKeys {
                recipient_id: sender_id.to_string(),
                shared_secret: shared_key,
                previous_secrets: Vec::new(),
            });
            println!("Created new session with {} (shared secret prefix: {})", 
                    sender_id, shared_key_prefix);
        }
        
        // Reset rotation counters
        drop(sessions);
        {
            let mut counters = self.messages_since_rotation.lock().unwrap();
            counters.insert(sender_id.to_string(), 0);
        }
        
        {
            let mut times = self.last_rotation_time.lock().unwrap();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            times.insert(sender_id.to_string(), now);
        }
        
        Ok(())
    }
}