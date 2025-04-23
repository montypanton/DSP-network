use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub public_key: String, // Base64 encoded Kyber public key
    pub display_name: String,
    pub ephemeral_key: Option<String>, // X25519 ephemeral public key
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender_id: String,
    pub recipient_id: Option<String>, // None for broadcast
    pub encrypted_data: String, // Base64 encoded encrypted data
    pub nonce: String, // Base64 encoded nonce for ChaCha20-Poly1305
    pub message_type: MessageType,
    pub timestamp: u64,
    // For forward secrecy
    pub ephemeral_public: Option<String>, // New X25519 ephemeral public key
    #[serde(default)] // This ensures backward compatibility with older messages
    pub is_initial_kyber: bool, // Flag to indicate if this is an initial message using Kyber
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MessageType {
    DeviceAnnounce,    // Announce device presence
    TextMessage,       // Regular text message
    KeyExchange,       // Key exchange for forward secrecy
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextMessage {
    pub content: String,
    pub from_name: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    pub recipient_id: String,
    pub shared_secret: Vec<u8>, // Current shared secret
    pub previous_secrets: Vec<Vec<u8>>, // Previous secrets for message decryption
}