use super::keys::SecretKey;
use super::plaintext::Plaintext;
use super::poly::Poly;

#[derive(Debug)]
pub struct Ciphertext {
    pub c_0: Poly,
    pub c_1: Poly,
}

impl Ciphertext {
    pub fn decrypt(&self, secret_key: SecretKey, t: i64) -> Plaintext {
        let s = secret_key.poly;
        let q = self.c_0.q;

        let delta_inv = t as f64 / q as f64;
        let raw = (self.c_0.clone() + self.c_1.clone() * s) * delta_inv;
        let poly = raw.modulo(t);
        Plaintext { poly, t }
    }
}
