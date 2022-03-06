use super::ciphertext::Ciphertext;
use super::keys::PublicKey;
use super::poly::Poly;
use super::random_source;
use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct Plaintext {
    pub poly: Poly,
    pub t: i64,
}

impl Plaintext {
    pub fn new(msg: Vec<i64>, t: i64, q: i64) -> Plaintext {
        // The plaintext space is taken as R_t for some integer t > 1.
        assert!(t > 1);
        Plaintext {
            poly: Poly {
                dimension: msg.len(),
                val: msg,
                q,
            },
            t,
        }
    }

    // TODO(cathie): change this to use &PublicKey, to prevent unnecessary cloning
    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        pub_key: PublicKey,
        std_dev: f64,
        rng: &mut T,
    ) -> Ciphertext {
        assert!(self.poly.q == pub_key.p_0.q);
        assert!(pub_key.p_0.q == pub_key.p_1.q);
        let q = self.poly.q;
        let dimension = self.poly.dimension;
        let m = self.poly.clone();

        let u = random_source::get_uniform(2, dimension, q, rng);
        let e_1 = random_source::get_gaussian(std_dev, dimension, q, rng);
        let e_2 = random_source::get_gaussian(std_dev, dimension, q, rng);

        let delta = (q as f64 / self.t as f64).floor() as i64;

        // TODO: add the multiplication by delta
        let c_0 = pub_key.p_0 * u.clone() + e_1 + m * delta;
        let c_1 = pub_key.p_1 * u + e_2;
        Ciphertext { c_0, c_1 }
    }
}
