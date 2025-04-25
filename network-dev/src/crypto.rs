use pqcrypto_kyber::kyber768::{self, PublicKey, SecretKey};
use pqcrypto_traits::kem::{PublicKey as PQPublicKey, SharedSecret as _, Ciphertext as _};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public, StaticSecret};
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
    
    // For key rotation
    pub messages_since_rotation: Arc<Mutex<HashMap<String, usize>>>,
    pub rotation_interval: usize,
    pub last_rotation_time: Arc<Mutex<HashMap<String, u64>>>,
    pub time_rotation_interval: u64,
    
    // X25519 static keypair for consistent sessions
    pub x25519_static_secret: StaticSecret,
    pub x25519_static_public: X25519Public,
}

impl CryptoContext {
    pub fn new() -> Self {
        // Generate a new Kyber keypair
        let (kyber_public_key, kyber_secret_key) = kyber768::keypair();
        
        // Generate a unique device ID
        let mut device_id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut device_id_bytes);
        let device_id = hex::encode(device_id_bytes);
        
        // Generate static X25519 keypair
        let x25519_static_secret = StaticSecret::new(OsRng);
        let x25519_static_public = X25519Public::from(&x25519_static_secret);
        
        Self {
            device_id,
            kyber_secret_key,
            kyber_public_key,
            session_keys: Arc::new(Mutex::new(HashMap::new())),
            messages_since_rotation: Arc::new(Mutex::new(HashMap::new())),
            rotation_interval: 50,
            last_rotation_time: Arc::new(Mutex::new(HashMap::new())),
            time_rotation_interval: 300,
            x25519_static_secret,
            x25519_static_public,
        }
    }
    
    // Configure key rotation
    pub fn configure_rotation(&mut self, message_interval: usize, time_interval_secs: u64) {
        self.rotation_interval = message_interval;
        self.time_rotation_interval = time_interval_secs;
        println!("Configured key rotation: every {} messages or {} seconds", 
                 message_interval, time_interval_secs);
    }
    
    // Create device info for sharing
    pub fn get_device_info(&self, display_name: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: self.device_id.clone(),
            public_key: BASE64.encode(self.kyber_public_key.as_bytes()),
            display_name: display_name.to_string(),
            // Share static X25519 public key instead of ephemeral
            ephemeral_key: Some(BASE64.encode(self.x25519_static_public.as_bytes())),
        }
    }
    
    // Create or update a session with another device
    pub fn create_or_update_session(&self, peer_id: &str, peer_x25519_key: &[u8]) -> Result<(), String> {
        println!("Setting up X25519 session with {}", peer_id);
        
        // Validate peer key
        if peer_x25519_key.len() != 32 {
            return Err(format!("Invalid X25519 public key size: {} bytes, expected 32", peer_x25519_key.len()));
        }
        
        // Convert bytes to X25519 public key
        let peer_public = match X25519Public::from_bytes(peer_x25519_key) {
            Ok(key) => key,
            Err(_) => return Err("Invalid X25519 public key format".to_string()),
        };
        
        // Use our static secret to derive shared secret with peer
        let shared_secret = self.x25519_static_secret.diffie_hellman(&peer_public);
        
        // Derive a deterministic session key from the shared secret
        let session_key = self.derive_deterministic_key(peer_id, &shared_secret.to_bytes());
        
        // Store or update the session
        let mut sessions = self.session_keys.lock().unwrap();
        
        if let Some(session) = sessions.get_mut(peer_id) {
            // Store previous key for backward compatibility
            session.previous_secrets.push(session.shared_secret.clone());
            if session.previous_secrets.len() > 5 {
                session.previous_secrets.remove(0);
            }
            
            // Debug output
            let key_prefix = hex::encode(&session_key[0..4]);
            
            // Update with new key
            session.shared_secret = session_key;
            println!("Updated existing session with {} (shared key prefix: {})", peer_id, key_prefix);
        } else {
            // Debug output
            let key_prefix = hex::encode(&session_key[0..4]);
            
            // Create new session
            sessions.insert(peer_id.to_string(), SessionKeys {
                recipient_id: peer_id.to_string(),
                shared_secret: session_key,
                previous_secrets: Vec::new(),
            });
            println!("Created new session with {} (shared key prefix: {})", peer_id, key_prefix);
        }
        
        // Reset rotation tracking
        drop(sessions);
        {
            let mut counters = self.messages_since_rotation.lock().unwrap();
            counters.insert(peer_id.to_string(), 0);
        }
        
        {
            let mut times = self.last_rotation_time.lock().unwrap();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            times.insert(peer_id.to_string(), now);
        }
        
        Ok(())
    }
    
    // Derive a deterministic key using peer ID and shared secret
    fn derive_deterministic_key(&self, peer_id: &str, shared_secret: &[u8]) -> Vec<u8> {
        // Arrange IDs in deterministic order for consistent key derivation
        let (first_id, second_id) = if self.device_id < peer_id.to_string() {
            (self.device_id.as_str(), peer_id)
        } else {
            (peer_id, self.device_id.as_str())
        };
        
        // Create context for key derivation
        let mut context = Vec::with_capacity(64);
        context.extend_from_slice(b"SECURE-MSG-KEY-");
        context.extend_from_slice(first_id.as_bytes());
        context.extend_from_slice(b"-");
        context.extend_from_slice(second_id.as_bytes());
        
        // Use SHA-256 for key derivation
        let mut kdf = Context::new(&SHA256);
        kdf.update(&context);
        kdf.update(shared_secret);
        let digest = kdf.finish();
        
        let key = digest.as_ref().to_vec();
        println!("Derived key (prefix): {}", hex::encode(&key[0..4]));
        
        key
    }
    
    // Generate a random ephemeral keypair for temporary use
    pub fn generate_ephemeral_keypair(&self) -> (EphemeralSecret, X25519Public) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519Public::from(&secret);
        (secret, public)
    }
    
    // Encrypt using session key
    pub fn encrypt_with_session(&self, recipient_id: &str, message: &[u8]) -> Result<(Vec<u8>, bool), String> {
        // Check if we need to rotate keys
        let should_rotate = self.should_rotate_key(recipient_id)?;
        
        // Get the current session key
        let shared_secret = {
            let sessions = self.session_keys.lock().unwrap();
            if let Some(session) = sessions.get(recipient_id) {
                session.shared_secret.clone()
            } else {
                return Err(format!("No session established with {}", recipient_id));
            }
        };
        
        // Create AES-GCM cipher
        let cipher = match Aes256Gcm::new_from_slice(&shared_secret[0..32]) {
            Ok(c) => c,
            Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
        };
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let encrypted_data = match cipher.encrypt(nonce, message) {
            Ok(ciphertext) => ciphertext,
            Err(e) => return Err(format!("Encryption failed: {}", e)),
        };
        
        // Combine nonce and encrypted data
        let mut result = Vec::new();
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted_data);
        
        if should_rotate {
            // Mark rotation in message count
            let mut counters = self.messages_since_rotation.lock().unwrap();
            *counters.entry(recipient_id.to_string()).or_insert(0) = 0;
            
            // Update rotation time
            let mut times = self.last_rotation_time.lock().unwrap();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            times.insert(recipient_id.to_string(), now);
            
            println!("Key rotation requested with message");
        }
        
        Ok((result, should_rotate))
    }
    
    // Check if key rotation is needed
    fn should_rotate_key(&self, recipient_id: &str) -> Result<bool, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let rotate_by_count;
        let rotate_by_time;
        
        // Check message count
        {
            let mut counts = self.messages_since_rotation.lock().unwrap();
            let count = counts.entry(recipient_id.to_string()).or_insert(0);
            *count += 1;
            rotate_by_count = *count >= self.rotation_interval;
            
            if rotate_by_count {
                println!("Key rotation triggered by message count: {}/{}", 
                        *count, self.rotation_interval);
            }
        }
        
        // Check time
        {
            let times = self.last_rotation_time.lock().unwrap();
            let last_time = times.get(recipient_id).unwrap_or(&now);
            rotate_by_time = now - *last_time >= self.time_rotation_interval;
            
            if rotate_by_time {
                println!("Key rotation triggered by time: {} seconds since last rotation", 
                        now - *last_time);
            }
        }
        
        Ok(rotate_by_count || rotate_by_time)
    }
    
    // Decrypt using session key
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
                            Err(_) => continue,
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
    
    // Kyber-based encryption for initial or fallback
    pub fn encrypt_message(&self, recipient_public_key_b64: &str, message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        // Decode the recipient's public key
        let recipient_public_key_bytes = BASE64.decode(recipient_public_key_b64)
            .map_err(|_| "Invalid public key encoding".to_string())?;
        
        // Validate key size
        let expected_size = kyber768::public_key_bytes();
        if recipient_public_key_bytes.len() != expected_size {
            return Err(format!("Invalid public key size: {} bytes, expected {} bytes for Kyber768", 
                             recipient_public_key_bytes.len(), expected_size));
        }
        
        // Create PublicKey from bytes
        let recipient_public_key = match PublicKey::from_bytes(&recipient_public_key_bytes) {
            Ok(pk) => pk,
            Err(_) => return Err("Invalid public key format".to_string()),
        };
        
        // Perform Kyber key encapsulation
        let (ciphertext, shared_secret) = kyber768::encapsulate(&recipient_public_key);
        
        // Derive AES key from shared secret
        let mut context = Context::new(&SHA256);
        context.update(shared_secret.as_bytes());
        let digest = context.finish();
        let key_bytes = digest.as_ref();
        
        // Create AES-GCM cipher
        let cipher = match Aes256Gcm::new_from_slice(key_bytes) {
            Ok(c) => c,
            Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
        };
        
        // Generate random nonce
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
    
    // Kyber-based decryption
    pub fn decrypt_message(&self, ciphertext: &[u8], nonce: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        // Convert to Kyber ciphertext
        let kyber_ciphertext = match kyber768::Ciphertext::from_bytes(ciphertext) {
            Ok(ct) => ct,
            Err(_) => return Err("Invalid ciphertext format".to_string()),
        };
        
        if nonce.len() != 12 {
            return Err(format!("Invalid nonce size: {} bytes, expected 12", nonce.len()));
        }
        
        // Decapsulate shared secret
        let shared_secret = kyber768::decapsulate(&kyber_ciphertext, &self.kyber_secret_key);
        
        // Derive AES key
        let mut context = Context::new(&SHA256);
        context.update(shared_secret.as_bytes());
        let digest = context.finish();
        let key_bytes = digest.as_ref();
        
        // Create AES cipher
        let cipher = match Aes256Gcm::new_from_slice(key_bytes) {
            Ok(c) => c,
            Err(_) => return Err("Failed to create AES-256-GCM cipher".to_string()),
        };
        
        // Decrypt
        let nonce = Nonce::from_slice(nonce);
        match cipher.decrypt(nonce, encrypted_data) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(format!("Decryption failed: {}", e)),
        }
    }
}