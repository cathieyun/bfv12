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
}

#[derive(Clone, Debug)]
pub struct RelinearizationKey1 {
    pub val: Vec<(Poly, Poly)>, // TODO(cathie) rename this to avoid confusion.
    pub base: i64,
    pub l: usize,
}

#[derive(Clone, Debug)]
pub struct RelinearizationKey2 {
    pub rlk_0: Poly,
    pub rlk_1: Poly,
    pub p: i64,
}

impl SecretKey {
    // Generate a secret key by sampling the coefficients of s uniformly
    // from R_2, which is the set {-1, 0, 1}.
    pub fn generate<T: RngCore + CryptoRng>(degree: usize, rng: &mut T) -> SecretKey {
        SecretKey {
            poly: random_source::get_uniform(2, degree, rng),
        }
    }

    pub fn public_key_gen<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        rng: &mut T,
    ) -> PublicKey {
        let s = self.poly.clone();
        let degree = s.degree();

        let a = random_source::get_uniform(q, degree, rng);
        let e = random_source::get_gaussian(std_dev, degree, rng);
        let p_1 = a.clone();
        let p_0 = (-(a.clone() * s.clone() + e)).modulo(q, degree);

        PublicKey { p_0, p_1 }
    }

    pub fn relinearization_key_gen_1<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        rng: &mut T,
        base: i64,
    ) -> RelinearizationKey1 {
        let degree = self.poly.degree();
        let s = self.poly.clone();
        // l is the number of levels to decompose s^2 and c_2 into.
        // l is a function of base (T in the paper): l = floor(log_T(q)).
        let l = (q as f64).log(base as f64).floor() as usize;

        let val = (0..l)
            .map(|i| {
                let a_i = random_source::get_uniform(q, degree, rng);
                let e_i = random_source::get_gaussian(std_dev, degree, rng);
                let base_i = base.pow(i as u32);
                let rlk_i_raw = -(a_i.clone() * s.clone() + e_i) + s.clone() * s.clone() * base_i;
                let rlk_i = rlk_i_raw.modulo(q, degree);
                (rlk_i, a_i)
            })
            .collect();
        RelinearizationKey1 { val, base, l }
    }

    // pub fn relinearization_key_gen_2<T: RngCore + CryptoRng>(
    //     &self,
    //     std_dev: f64,
    //     rng: &mut T,
    //     p: i64,
    // ) -> RelinearizationKey2 {
    //     let q = self.poly.q;
    //     let mut s = self.poly.clone();
    //     // Change the modulus of all polynomials to p*q
    //     s.q = p * q;

    //     let a = random_source::get_uniform(p * q, self.poly.dimension, p * q, rng);
    //     let e = random_source::get_gaussian(std_dev, self.poly.dimension, p * q, rng);
    //     let rlk_0 = -(a.clone() * s.clone() + e) + s.clone() * s.clone() * p;

    //     RelinearizationKey2 {
    //         rlk_0,
    //         rlk_1: a,
    //         p,
    //     }
    // }
}
