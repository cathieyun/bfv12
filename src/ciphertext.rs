use super::keys::{RelinearizationKey1, SecretKey};
use super::plaintext::Plaintext;
use super::poly::Poly;
use std::ops::{Add, Neg, Sub};

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c_0: Poly,
    pub c_1: Poly,
    pub q: i64,
    pub t: i64,
}

impl Ciphertext {
    pub fn decrypt(&self, secret_key: &SecretKey) -> Plaintext {
        let s = &secret_key.poly;
        let degree = s.degree();

        let delta_inv = self.t as f64 / self.q as f64;
        let raw = (self.c_0.clone() + self.c_1.clone() * s.clone()).modulo(self.q, degree);
        let poly = (raw * delta_inv).modulo(self.t, degree);

        Plaintext {
            poly,
            q: self.q,
            t: self.t,
        }
    }

    // TODO(cathie): make this a private function since it should never be called externally.
    // (this requires getting tests on private functions to work).
    pub fn basic_mul(&self, other: Ciphertext) -> (Poly, Poly, Poly) {
        let degree = self.c_0.degree();
        assert_eq!(degree, self.c_1.degree());
        assert_eq!(degree, other.c_0.degree());
        assert_eq!(degree, other.c_1.degree());

        let out_0_raw = self.c_0.clone() * other.c_0.clone();
        let out_1_raw = self.c_0.clone() * other.c_1.clone() + self.c_1.clone() * other.c_0.clone();
        let out_2_raw = self.c_1.clone() * other.c_1.clone();

        let delta_inv = self.t as f64 / self.q as f64;
        let out_0 = (out_0_raw * delta_inv).modulo(self.q, degree);
        let out_1 = (out_1_raw * delta_inv).modulo(self.q, degree);
        let out_2 = (out_2_raw * delta_inv).modulo(self.q, degree);

        (out_0, out_1, out_2)
    }

    pub fn mul_1(&self, other: Ciphertext, rlk: &RelinearizationKey1) -> Ciphertext {
        let (c_0, c_1, c_2) = self.basic_mul(other);

        self.relinearization_1(c_0, c_1, c_2, rlk)
    }

    fn relinearization_1(
        &self,
        c_0: Poly,
        c_1: Poly,
        c_2: Poly,
        rlk: &RelinearizationKey1,
    ) -> Ciphertext {
        let degree = c_0.degree();

        // Decompose c_2 in base T (rlk_base), such that:
        // $ c_2 = \sum_{i=0}^l c_2^(i) T^i $ with $ c_2^(i) \in R_T $
        let c_2_dec: Vec<Poly> = c_2.decompose(rlk.l, rlk.base);

        // Calculate the contributions of the decomposed c_2 for c_0 and c_1.
        let mut c_2_0 = Poly::new(vec![0; degree]);
        let mut c_2_1 = Poly::new(vec![0; degree]);
        for i in 0..(rlk.l as usize) {
            // Calculate the sum of the first entry of the relinearization key and decomposed c_2:
            // $ \sum_{i=0}^l rlk[i][0] * c_2^(i) $
            c_2_0 = c_2_0 + rlk.val[i].0.clone() * c_2_dec[i].clone();

            // Calculate the sum of the second entry of the relinearization key and decomposed c_2:
            // $ \sum_{i=0}^l rlk[i][1] * c_2^(i) $
            c_2_1 = c_2_1 + rlk.val[i].1.clone() * c_2_dec[i].clone();
        }

        Ciphertext {
            c_0: c_0 + c_2_0,
            c_1: c_1 + c_2_1,
            q: self.q,
            t: self.t,
        }
    }
    /*
    pub fn mul_2(&self, other: Ciphertext, rlk: RelinearizationKey2) -> Ciphertext {
        let (c_0, c_1, c_2) = self._basic_mul(other);

        self.relinearization_2(c_0, c_1, c_2, rlk)
    }

    fn relinearization_2(
        &self,
        c_0: Poly,
        c_1: Poly,
        c_2: Poly,
        rlk: RelinearizationKey2,
    ) -> Ciphertext {
        let q = c_0.q;
        let mut rlk_0_q = rlk.rlk_0.clone();
        let mut rlk_1_q = rlk.rlk_1.clone();
        // Change rlk to be mod q instead of p * q
        rlk_0_q.q = q;
        rlk_1_q.q = q;

        let p_inv = 1.0 / rlk.p as f64;

        let c_2_0 = c_2.clone() * rlk_0_q * p_inv;
        let c_2_1 = c_2.clone() * rlk_1_q * p_inv;
        Ciphertext {
            c_0: c_0 + c_2_0,
            c_1: c_1 + c_2_1,
            t: self.t,
        }
    }*/
}

impl Add<Ciphertext> for Ciphertext {
    type Output = Self;
    fn add(self, other: Ciphertext) -> Self::Output {
        Ciphertext {
            c_0: self.c_0 + other.c_0,
            c_1: self.c_1 + other.c_1,
            q: self.q,
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
            q: self.q,
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
