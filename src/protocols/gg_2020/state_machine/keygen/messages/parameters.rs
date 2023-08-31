use std::fmt::Debug;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub threshold: u16,  
    pub share_count: u16,
}

impl Parameters {
    pub fn new(t:u16, n:u16) -> Self {
        Self {
            threshold:t,
            share_count: n
        }
    }
}
