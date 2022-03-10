use super::ciphertext::Ciphertext;
use super::keys::PublicKey;
use super::poly::Poly;
use super::random_source;
use rand::{CryptoRng, RngCore};

#[derive(Debug)]
pub struct Plaintext {
    pub poly: Poly,
    pub q: i64,
    pub t: i64,
}

impl Plaintext {
    pub fn new(msg: Vec<i64>, t: i64, q: i64) -> Plaintext {
        // The plaintext space is taken as R_t for some integer t > 1.
        assert!(t > 1);
        Plaintext {
            poly: Poly::new(msg),
            q,
            t,
        }
    }

    pub fn rand<T: RngCore + CryptoRng>(
        degree: usize,
        t: i64,
        q: i64,
        rng: &mut T
    ) -> Plaintext {
        assert!(t > 1);
        Plaintext {
            poly: random_source::get_uniform(t, degree, rng),
            q,
            t,
        }
    }

    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        pub_key: &PublicKey,
        std_dev: f64,
        rng: &mut T,
    ) -> Ciphertext {
        assert_eq!(self.poly.degree(), pub_key.p_0.degree());
        let q = self.q;
        let degree = self.poly.degree();
        let m = self.poly.clone();

        let u = random_source::get_uniform(2, degree, rng);
        let e_1 = random_source::get_gaussian(std_dev, degree, rng);
        let e_2 = random_source::get_gaussian(std_dev, degree, rng);

        let delta = (q as f64 / self.t as f64).floor() as i64;

        let c_0 = (pub_key.p_0.clone() * u.clone() + e_1 + m * delta) % (q, degree);
        let c_1 = (pub_key.p_1.clone() * u + e_2) % (q, degree);

        Ciphertext {
            c_0,
            c_1,
            q: self.q,
            t: self.t,
        }
    }
}
