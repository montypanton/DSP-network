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

use crate::message::{DeviceInfo, SessionKeys};

// The kyber768 ciphertext size (from the spec: it's 1088 bytes)
const KYBER_CIPHERTEXT_SIZE: usize = 1088;

// The crypto context for a device
pub struct CryptoContext {
    pub device_id: String,
    pub kyber_secret_key: SecretKey,
    pub kyber_public_key: PublicKey,
    pub session_keys: Arc<Mutex<HashMap<String, SessionKeys>>>,
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
        }
    }
    
    // Create a device info object for sharing
    pub fn get_device_info(&self, display_name: &str) -> DeviceInfo {
        DeviceInfo {
            device_id: self.device_id.clone(),
            public_key: BASE64.encode(self.kyber_public_key.as_bytes()),
            display_name: display_name.to_string(),
            ephemeral_key: None,
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
            
        let recipient_public_key = match PublicKey::from_bytes(&recipient_public_key_bytes) {
            Ok(pk) => pk,
            Err(_) => return Err("Invalid public key format".to_string()),
        };
        
        // Perform Kyber key encapsulation
        let (ciphertext, shared_secret) = kyber768::encapsulate(&recipient_public_key);
        
        // Use the shared secret to create a ChaCha20-Poly1305 key
        let aead_key = Key::from_slice(shared_secret.as_bytes());
        let cipher = ChaCha20Poly1305::new(aead_key);
        
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the message
        let encrypted_data = cipher.encrypt(nonce, message)
            .map_err(|e| format!("Encryption failed: {}", e))?;
            
        // Return the ciphertext and nonce for use in the message
        // Note: The actual ciphertext bytes are returned here, not just the nonce
        Ok((ciphertext.as_bytes().to_vec(), nonce_bytes.to_vec()))
    }
    
    // Decrypt a message using Kyber and ChaCha20-Poly1305
    pub fn decrypt_message(&self, ciphertext: &[u8], nonce: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        // Validate input sizes
        if ciphertext.len() != KYBER_CIPHERTEXT_SIZE {
            return Err(format!("Invalid ciphertext size: {} bytes, expected {}", 
                            ciphertext.len(), KYBER_CIPHERTEXT_SIZE));
        }
        
        if nonce.len() != 12 {
            return Err(format!("Invalid nonce size: {} bytes, expected 12", nonce.len()));
        }
        
        // Convert the ciphertext bytes to a Kyber ciphertext
        let kyber_ciphertext = match kyber768::Ciphertext::from_bytes(ciphertext) {
            Ok(ct) => ct,
            Err(_) => return Err("Invalid ciphertext format".to_string()),
        };
        
        // Decapsulate the shared secret
        let shared_secret = kyber768::decapsulate(&kyber_ciphertext, &self.kyber_secret_key);
        
        // Create the ChaCha20-Poly1305 cipher
        let aead_key = Key::from_slice(shared_secret.as_bytes());
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
        let recipient_pubkey = match X25519Public::from(<[u8; 32]>::try_from(recipient_ephemeral_key).unwrap()) {
            pub_key => pub_key,
        };
        
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
        } else {
            // Create new session
            sessions.insert(recipient_id.to_string(), SessionKeys {
                recipient_id: recipient_id.to_string(),
                shared_secret: shared_secret.as_bytes().to_vec(),
                previous_secrets: Vec::new(),
            });
        }
        
        Ok(ephemeral_public)
    }
    
    // Encrypt a message using the forward secrecy session
    pub fn encrypt_with_session(&self, recipient_id: &str, message: &[u8]) -> Result<(Vec<u8>, Option<X25519Public>), String> {
        let should_refresh = false;
        let shared_secret;
        
        // Get the current session key
        {
            let sessions = self.session_keys.lock().unwrap();
            if let Some(session) = sessions.get(recipient_id) {
                shared_secret = session.shared_secret.clone();
                // Decide if we should refresh the key (e.g., every 10 messages)
                // This is a simplified approach - in a real system, you'd use a more sophisticated key rotation policy
                // should_refresh = rand::random::<u8>() < 20; // ~8% chance of refreshing
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
        
        // If we should refresh, generate a new ephemeral key
        let new_ephemeral = if should_refresh {
            let (_, public) = self.generate_ephemeral_keypair();
            Some(public)
        } else {
            None
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
                Ok(plaintext) => return Ok(plaintext),
                Err(_) => {
                    // Try previous keys
                    for prev_secret in &session.previous_secrets {
                        let prev_key = Key::from_slice(&prev_secret[0..32]);
                        let prev_cipher = ChaCha20Poly1305::new(prev_key);
                        
                        if let Ok(plaintext) = prev_cipher.decrypt(nonce, ciphertext) {
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