use crate::message::DeviceInfo;
use std::sync::{Arc, Mutex, Once};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DeviceManager {
    known_devices: Arc<Mutex<HashMap<String, DeviceInfo>>>,
    last_seen: Arc<Mutex<HashMap<String, u64>>>,
}

// Static instance for singleton pattern
static mut INSTANCE: Option<Arc<DeviceManager>> = None;
static INIT: Once = Once::new();

impl DeviceManager {
    pub fn new() -> Self {
        Self {
            known_devices: Arc::new(Mutex::new(HashMap::new())),
            last_seen: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    // Get the singleton instance
    pub fn get_instance() -> Arc<DeviceManager> {
        unsafe {
            INIT.call_once(|| {
                INSTANCE = Some(Arc::new(DeviceManager::new()));
            });
            
            INSTANCE.clone().unwrap()
        }
    }
    
    // Add or update a device
    pub fn update_device(&self, device: DeviceInfo) {
        let device_id = device.device_id.clone();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        {
            let mut devices = self.known_devices.lock().unwrap();
            devices.insert(device_id.clone(), device);
        }
        
        {
            let mut last_seen = self.last_seen.lock().unwrap();
            last_seen.insert(device_id, now);
        }
    }
    
    // Get a list of all known devices
    pub fn list_devices(&self) -> Vec<DeviceInfo> {
        let devices = self.known_devices.lock().unwrap();
        devices.values().cloned().collect()
    }
    
    // Get a specific device by ID
    pub fn get_device(&self, device_id: &str) -> Option<DeviceInfo> {
        let devices = self.known_devices.lock().unwrap();
        devices.get(device_id).cloned()
    }
    
    // Update the MQTT messenger to use the device manager singleton
    pub fn cleanup_inactive_devices(&self, inactive_threshold_secs: u64) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut to_remove = Vec::new();
        
        {
            let last_seen = self.last_seen.lock().unwrap();
            for (id, last) in last_seen.iter() {
                if now - last > inactive_threshold_secs {
                    to_remove.push(id.clone());
                }
            }
        }
        
        if !to_remove.is_empty() {
            let mut devices = self.known_devices.lock().unwrap();
            let mut last_seen = self.last_seen.lock().unwrap();
            
            for id in to_remove {
                devices.remove(&id);
                last_seen.remove(&id);
            }
        }
    }
}