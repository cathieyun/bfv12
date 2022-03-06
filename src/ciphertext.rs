use super::keys::SecretKey;
use super::plaintext::Plaintext;
use super::poly::Poly;
use std::ops::{Add, Mul, Neg, Sub};

#[derive(Debug)]
pub struct Ciphertext {
    pub c_0: Poly,
    pub c_1: Poly,
}

impl Ciphertext {
    // TODO(cathie): change this to use &SecretKey, to prevent unnecessary cloning
    pub fn decrypt(&self, secret_key: SecretKey, t: i64) -> Plaintext {
        let s = secret_key.poly;
        let q = self.c_0.q;

        let delta_inv = t as f64 / q as f64;
        let raw = (self.c_0.clone() + self.c_1.clone() * s) * delta_inv;
        let poly = raw.unsigned_modulo(t);
        Plaintext { poly, t }
    }
}

impl Add<Ciphertext> for Ciphertext {
    type Output = Self;
    fn add(self, other: Ciphertext) -> Self::Output {
        Ciphertext {
            c_0: self.c_0 + other.c_0,
            c_1: self.c_1 + other.c_1,
        }
    }
}

impl Sub<Ciphertext> for Ciphertext {
    type Output = Self;
    fn sub(self, other: Ciphertext) -> Self::Output {
        Ciphertext {
            c_0: self.c_0 - other.c_0,
            c_1: self.c_1 - other.c_1,
        }
    }
}

impl Neg for Ciphertext {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        self.c_0 = -self.c_0;
        self.c_1 = -self.c_1;
        self
    }
}
