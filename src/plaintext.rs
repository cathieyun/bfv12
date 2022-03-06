use super::keys::PublicKey;
use super::ciphertext::Ciphertext;
use super::random_source;

pub struct Plaintext {
    pub val: Vec<i64>,
    pub t: u64,
    pub dimension: usize,
}

impl Plaintext {
    pub fn new(val: Vec<i64>, t: u64) -> Plaintext {
        // The plaintext space is taken as R_t for some integer t > 1.
        assert!(t > 1);
        Plaintext {
            dimension: val.len(),
            val,
            t,
        }
    }
}