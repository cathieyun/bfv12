use super::keys::{RelinearizationKey1, RelinearizationKeySimple, SecretKey};
use super::plaintext::Plaintext;
use super::poly::Poly;
use std::ops::{Add, Neg, Sub};

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c_0: Poly,
    pub c_1: Poly,
    pub t: i64,
}

impl Ciphertext {
    // TODO(cathie): change this to use &SecretKey, to prevent unnecessary cloning
    pub fn decrypt(&self, secret_key: SecretKey) -> Plaintext {
        let s = secret_key.poly;

        let delta_inv = self.t as f64 / self.c_0.q as f64;
        let raw = (self.c_0.clone() + self.c_1.clone() * s) * delta_inv;
        let poly = raw.unsigned_modulo(self.t);
        Plaintext { poly, t: self.t }
    }

    pub fn mul_simple(&self, other: Ciphertext, rlk: RelinearizationKeySimple) -> Ciphertext {
        let (c_0, c_1, c_2) = self.basic_mul(other);

        self.relinearization_simple(c_0, c_1, c_2, rlk)
    }

    fn relinearization_simple(
        &self,
        c_0: Poly,
        c_1: Poly,
        c_2: Poly,
        rlk: RelinearizationKeySimple,
    ) -> Ciphertext {
        Ciphertext {
            c_0: c_0 + rlk.ek_0 * c_2.clone(),
            c_1: c_1 + rlk.ek_1 * c_2,
            t: self.t,
        }
    }

    fn basic_mul(&self, other: Ciphertext) -> (Poly, Poly, Poly) {
        let delta_inv = self.t as f64 / self.c_0.q as f64;
        println!("delta_inv: {:?}", delta_inv);
        let out_0 = self.c_0.clone() * other.c_0.clone() * delta_inv;
        let out_1 =
            (self.c_0.clone() * other.c_1.clone() + self.c_1.clone() * other.c_0) * delta_inv;
        let out_2 = self.c_1.clone() * other.c_1 * delta_inv;
        (out_0, out_1, out_2)
    }

    pub fn mul_1(&self, other: Ciphertext, rlk: RelinearizationKey1) -> Ciphertext {
        let (c_0, c_1, c_2) = self.basic_mul(other);

        self.relinearization_1(c_0, c_1, c_2, rlk)
    }

    fn relinearization_1(
        &self,
        c_0: Poly,
        c_1: Poly,
        c_2: Poly,
        rlk: RelinearizationKey1,
    ) -> Ciphertext {
        println!("c_0: {:?}", c_0);
        println!("c_1: {:?}", c_1);
        // Decompose c_2 in base T (rlk_base), such that:
        // $ c_2 = \sum_{i=0}^l c_2^(i) T^i $ with $ c_2^(i) \in R_T $
        println!("c_2: {:?}", c_2);
        let c_2_dec: Vec<Poly> = c_2.decompose(rlk.l, rlk.base);

        println!("c_2 decomposed: {:?}", c_2_dec);

        // Calculate the contributions of the decomposed c_2 for c_0 and c_1.
        let mut c_2_0 = Poly::empty(self.c_0.dimension, self.c_0.q);
        let mut c_2_1 = Poly::empty(self.c_1.dimension, self.c_1.q);
        for i in 0..(rlk.l as usize) {
            // Calculate the sum of the first entry of the relinearization key and decomposed c_2:
            // $ \sum_{i=0}^l rlk[i][0] * c_2^(i) $
            c_2_0 = c_2_0 + rlk.rlk[i].0.clone() * c_2_dec[i].clone();

            // Calculate the sum of the second entry of the relinearization key and decomposed c_2:
            // $ \sum_{i=0}^l rlk[i][1] * c_2^(i) $
            c_2_1 = c_2_1 + rlk.rlk[i].1.clone() * c_2_dec[i].clone();
        }

        println!("rlk: {:?}", rlk);

        println!("c_2_0: {:?}", c_2_0);
        println!("c_2_1: {:?}", c_2_1);

        Ciphertext {
            c_0: c_0 + c_2_0,
            c_1: c_1 + c_2_1,
            t: self.t,
        }
    }
}

impl Add<Ciphertext> for Ciphertext {
    type Output = Self;
    fn add(self, other: Ciphertext) -> Self::Output {
        Ciphertext {
            c_0: self.c_0 + other.c_0,
            c_1: self.c_1 + other.c_1,
            t: self.t,
        }
    }
}

impl Sub<Ciphertext> for Ciphertext {
    type Output = Self;
    fn sub(self, other: Ciphertext) -> Self::Output {
        Ciphertext {
            c_0: self.c_0 - other.c_0,
            c_1: self.c_1 - other.c_1,
            t: self.t,
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
