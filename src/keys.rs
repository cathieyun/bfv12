use super::random_source;
use super::poly::Poly;

#[derive(Debug)]
pub struct SecretKey {
    pub poly: Poly,
}

pub struct PublicKey {  
    // TODO(cathie): add a struct to hold vectors
    pub p_0: Poly,
    pub p_1: Poly,
    pub dimension: usize,
    pub std_dev: f64,
    pub q: i64,
}

impl SecretKey {
    // TODO(cathie): add error management
    // Generate a secret key by sampling the coefficients of s uniformly
    // from R_2, which is the set {-1, 0, 1}.
    pub fn generate(dimension: usize, modulus: i64) -> SecretKey {
        SecretKey {
            poly: random_source::get_uniform(2, dimension, modulus),
        }
    }

    // TODO(cathie): are the dimensions for a, s, e all the same?
    pub fn to_pub_key(&self, q: i64, std_dev: f64, dimension: usize) -> PublicKey {
        let s = self.poly.clone();
        let a = random_source::get_uniform(q, dimension, q);
        let e = random_source::get_gaussian(std_dev, dimension, q);

        let p_1 = a.clone();
        let p_0 = -(a * s + e);

        PublicKey {
            p_0,
            p_1,
            dimension,
            std_dev,
            q,
        }
    }
}