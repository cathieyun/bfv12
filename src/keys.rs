use super::poly::Poly;
use super::random_source;
use rand::{CryptoRng, RngCore};

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub poly: Poly,
}

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub p_0: Poly,
    pub p_1: Poly,
    pub std_dev: f64,
}

impl SecretKey {
    // Generate a secret key by sampling the coefficients of s uniformly
    // from R_2, which is the set {-1, 0, 1}.
    pub fn generate<T: RngCore + CryptoRng>(
        dimension: usize,
        modulus: i64,
        rng: &mut T,
    ) -> SecretKey {
        SecretKey {
            poly: random_source::get_uniform(2, dimension, modulus, rng),
        }
    }

    pub fn to_pub_key<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        dimension: usize,
        rng: &mut T,
    ) -> PublicKey {
        let s = self.poly.clone();
        let a = random_source::get_uniform(q, dimension, q, rng);
        let e = random_source::get_gaussian(std_dev, dimension, q, rng);

        let p_1 = a.clone();
        let p_0 = -(a * s + e);

        PublicKey { p_0, p_1, std_dev }
    }
}
