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

// #[cfg(test)]
// mod tests {
//     use crate::*;
//     use rand::SeedableRng;

//     fn encrypt_decrypt_helper(msg: Vec<i64>, t: i64, q: i64, std_dev: f64) {
//         let dimension = msg.len();
//         let mut rng = rand::rngs::StdRng::seed_from_u64(18);

//         let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
//         let public_key = secret_key.to_pub_key(q, std_dev, dimension, &mut rng);

//         let plaintext = plaintext::Plaintext::new(msg, t, q);
//         let ciphertext = plaintext.encrypt(public_key, std_dev, &mut rng);

//         let decrypted = ciphertext.decrypt(secret_key, t);

//         assert_eq!(decrypted.poly.val, plaintext.poly.val);
//     }

//     // t = 2
//     #[test]
//     fn encrypt_decrypt_t2_dim2() {
//         encrypt_decrypt_helper(vec![0, 1], 2, 256, 3.2);
//     }

//     #[test]
//     fn encrypt_decrypt_t2_dim4() {
//         encrypt_decrypt_helper(vec![0, 1, 1, 0], 2, 256, 3.2);
//     }

//     #[test]
//     fn encrypt_decrypt_t2_dim8() {
//         encrypt_decrypt_helper(vec![0, 1, 1, 0, 0, 0, 1, 0], 2, 256, 3.2);
//     }

//     // t = 4
//     #[test]
//     fn encrypt_decrypt_t4_dim2() {
//         encrypt_decrypt_helper(vec![0, 3], 4, 256, 3.2);
//     }

//     #[test]
//     fn encrypt_decrypt_t4_dim4() {
//         encrypt_decrypt_helper(vec![0, 1, 2, 3], 4, 256, 3.2);
//     }

//     #[test]
//     fn encrypt_decrypt_t4_dim8() {
//         encrypt_decrypt_helper(vec![0, 1, 2, 3, 3, 2, 1, 0], 4, 256, 3.2);
//     }

//     // t = 8
//     #[test]
//     fn encrypt_decrypt_t8_dim4() {
//         encrypt_decrypt_helper(vec![0, 1, 2, 3], 8, 256, 3.2);
//     }

//     #[test]
//     fn encrypt_decrypt_t8_dim8() {
//         encrypt_decrypt_helper(vec![0, 1, 2, 3, 4, 5, 6, 7], 8, 256, 3.2);
//     }

//     // t = 16
//     #[test]
//     fn encrypt_decrypt_t16_dim2() {
//         encrypt_decrypt_helper(vec![0, 3], 16, 256, 3.2);
//     }

//     #[test]
//     fn encrypt_decrypt_t16_dim4() {
//         encrypt_decrypt_helper(vec![0, 1, 2, 3], 16, 256, 3.2);
//     }

//     #[test]
//     fn t32_dim2() {
//         encrypt_decrypt_helper(vec![0, 1], 32, 256, 3.2);
//     }
// }
