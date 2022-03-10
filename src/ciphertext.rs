use super::keys::{RelinearizationKey1, RelinearizationKey2, SecretKey};
use super::plaintext::Plaintext;
use super::poly::Poly;
use std::ops::{Add, Mul, Neg, Sub};

/// A BFV12 Ciphertext
///
/// * `c_0` = `[p_0 * u + e_1 + delta * m]_q`
/// * `c_1` = `[p_1 * u + e_2]_q`
/// * `q` = the ciphertext modulus
/// * `t` = the plaintext modulus
#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub(crate) c_0: Poly,
    pub(crate) c_1: Poly,
    pub(crate) q: i64,
    pub(crate) t: i64,
}

impl Ciphertext {
    /// Decrypt a ciphertext to recover a plaintext, given a secret key
    ///
    /// ```rust
    /// # extern crate rand;
    /// # use rand::SeedableRng;
    /// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
    /// # let std_dev = 3.2;
    /// # let degree = 4;
    /// # let q = 65536;
    /// # let t = 4;
    /// #
    /// use bfv::{Plaintext, SecretKey};
    /// let pt = Plaintext::new(vec![0, 1, 2, 3], t);
    ///
    /// let secret_key = SecretKey::generate(degree, &mut rng);
    /// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
    ///
    /// let ct = pt.encrypt(&public_key, std_dev, &mut rng);
    /// let decrypted = ct.decrypt(&secret_key);
    ///
    /// assert_eq!(decrypted, pt);
    /// ```
    pub fn decrypt(&self, secret_key: &SecretKey) -> Plaintext {
        let s = &secret_key.poly;
        let degree = s.degree();

        let delta_inv = self.t as f64 / self.q as f64;
        let raw = (self.c_0.clone() + self.c_1.clone() * s.clone()) % (self.q, degree);
        let poly = (raw * delta_inv) % (self.t, degree);

        Plaintext::new_from_poly(poly, self.t)
    }

    pub(crate) fn basic_mul(&self, other: Ciphertext) -> (Poly, Poly, Poly) {
        let degree = self.c_0.degree();
        assert_eq!(degree, self.c_1.degree());
        assert_eq!(degree, other.c_0.degree());
        assert_eq!(degree, other.c_1.degree());

        let out_0_raw = self.c_0.clone() * other.c_0.clone();
        let out_1_raw = self.c_0.clone() * other.c_1.clone() + self.c_1.clone() * other.c_0.clone();
        let out_2_raw = self.c_1.clone() * other.c_1.clone();

        let delta_inv = self.t as f64 / self.q as f64;
        let out_0 = (out_0_raw * delta_inv) % (self.q, degree);
        let out_1 = (out_1_raw * delta_inv) % (self.q, degree);
        let out_2 = (out_2_raw * delta_inv) % (self.q, degree);

        (out_0, out_1, out_2)
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

    fn relinearization_2(
        &self,
        c_0: Poly,
        c_1: Poly,
        c_2: Poly,
        rlk: &RelinearizationKey2,
    ) -> Ciphertext {
        let degree = c_0.degree();
        let p = rlk.p as f64;

        let c_2_0 = (c_2.clone() * rlk.rlk_0.clone() / p) % (self.q, degree);
        let c_2_1 = (c_2.clone() * rlk.rlk_1.clone() / p) % (self.q, degree);
        Ciphertext {
            c_0: (c_0 + c_2_0) % (self.q, degree),
            c_1: (c_1 + c_2_1) % (self.q, degree),
            q: self.q,
            t: self.t,
        }
    }
}

/// Add two ciphertexts. They can be of different degrees.
///
/// ```rust
/// # extern crate rand;
/// # use rand::SeedableRng;
/// #
/// # extern crate bfv;
/// # use bfv::{SecretKey, Plaintext};
/// #
/// # let t = 12;         // Plaintext modulus
/// # let q = 65536;      // Ciphertext modulus
/// # let std_dev = 3.2;  // Standard deviation for generating the error
/// # let degree = 4;     // Degree of polynomials used for encoding and encrypting messages
/// #
/// # // Generate a seeded RNG. Any Rng that imlements RngCore + CryptoRng can be used.
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
/// #
/// let secret_key = SecretKey::generate(degree, &mut rng);
/// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
///
/// let pt_1 = Plaintext::rand(degree, t, &mut rng);
/// let pt_2 = Plaintext::rand(degree, t, &mut rng);
/// let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
/// let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
///
/// // Add the ciphertexts: ct_1 + ct_2
/// let add_ct = ct_1 + ct_2;
///
/// // Decrypt the result of the addition
/// let add_pt = add_ct.decrypt(&secret_key);
///
/// // Compare the expected output to the decrypted output
/// let expected_pt = (pt_1.poly() + pt_2.poly()) % (t, degree);
/// assert_eq!(add_pt.poly(), expected_pt)
/// ```
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

/// Subtract one ciphertext from another. They can be of different degrees.
///
/// ```rust
/// # extern crate rand;
/// # use rand::SeedableRng;
/// #
/// # extern crate bfv;
/// # use bfv::{SecretKey, Plaintext};
/// #
/// # let t = 12;         // Plaintext modulus
/// # let q = 65536;      // Ciphertext modulus
/// # let std_dev = 3.2;  // Standard deviation for generating the error
/// # let degree = 4;     // Degree of polynomials used for encoding and encrypting messages
/// #
/// # // Generate a seeded RNG. Any Rng that imlements RngCore + CryptoRng can be used.
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
/// #
/// let secret_key = SecretKey::generate(degree, &mut rng);
/// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
///
/// let pt_1 = Plaintext::rand(degree, t, &mut rng);
/// let pt_2 = Plaintext::rand(degree, t, &mut rng);
/// let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
/// let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
///
/// // Subtract: ct_1 - ct_2
/// let sub_ct = ct_1 - ct_2;
///
/// // Decrypt the result of the subtraction
/// let sub_pt = sub_ct.decrypt(&secret_key);
///
/// // Compare the expected output to the decrypted output
/// let expected_pt = (pt_1.poly() - pt_2.poly()) % (t, degree);
/// assert_eq!(sub_pt.poly(), expected_pt)
/// ```
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

/// Take the negation of a ciphertext.
///
/// ```rust
/// # extern crate rand;
/// # use rand::SeedableRng;
/// #
/// # extern crate bfv;
/// # use bfv::{SecretKey, Plaintext};
/// #
/// # let t = 12;         // Plaintext modulus
/// # let q = 65536;      // Ciphertext modulus
/// # let std_dev = 3.2;  // Standard deviation for generating the error
/// # let degree = 4;     // Degree of polynomials used for encoding and encrypting messages
/// #
/// # // Generate a seeded RNG. Any Rng that imlements RngCore + CryptoRng can be used.
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
/// #
/// let secret_key = SecretKey::generate(degree, &mut rng);
/// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
///
/// let pt = Plaintext::rand(degree, t, &mut rng);
/// let ct = pt.encrypt(&public_key, std_dev, &mut rng);
///
/// // Negate: -ct
/// let neg_ct = -ct;
///
/// // Decrypt the result of the negation
/// let neg_pt = neg_ct.decrypt(&secret_key);
///
/// // Compare the expected output to the decrypted output
/// let expected_pt = -pt.poly() % (t, degree);
/// assert_eq!(neg_pt.poly(), expected_pt)
/// ```
impl Neg for Ciphertext {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        self.c_0 = -self.c_0;
        self.c_1 = -self.c_1;
        self
    }
}

/// Multiply two ciphertexts, using Relinearization Version 1.
/// Since multiplication requires a relinearization key, you must multiply a ciphertext
/// with a tuple of (Ciphertext, &RelinearizationKey1). The type of the relinearization
/// key determines whether the multiplication uses Relinearization Version 1 or 2.
///
/// ```rust
/// # extern crate rand;
/// # use rand::SeedableRng;
/// #
/// # extern crate bfv;
/// # use bfv::{SecretKey, Plaintext};
/// #
/// # let t = 12;         // Plaintext modulus
/// # let q = 65536;      // Ciphertext modulus
/// # let std_dev = 3.2;  // Standard deviation for generating the error
/// # let degree = 4;     // Degree of polynomials used for encoding and encrypting messages
/// # let rlk_base = (q as f64).log2() as i64; // The base for decomposition during relinearization
/// #
/// # // Generate a seeded RNG. Any Rng that imlements RngCore + CryptoRng can be used.
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
/// #
/// let secret_key = SecretKey::generate(degree, &mut rng);
/// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
/// let rlk_1 = secret_key.relin_key_gen_1(q, std_dev, &mut rng, rlk_base);
///
/// let pt_1 = Plaintext::rand(degree, t, &mut rng);
/// let pt_2 = Plaintext::rand(degree, t, &mut rng);
/// let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
/// let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
///
/// // Multiply the ciphertexts: ct_1 * ct_2
/// let mul_ct = ct_1 * (ct_2, &rlk_1);
///
/// // Decrypt the result of the multiplication
/// let mul_pt = mul_ct.decrypt(&secret_key);
///
/// // Compare the expected output to the decrypted output
/// let expected_pt = (pt_1.poly() * pt_2.poly()) % (t, degree);
/// assert_eq!(mul_pt.poly(), expected_pt)
/// ```
impl Mul<(Ciphertext, &RelinearizationKey1)> for Ciphertext {
    type Output = Self;
    fn mul(self, other: (Ciphertext, &RelinearizationKey1)) -> Self::Output {
        let (other_ct, rlk_1) = other;

        let (c_0, c_1, c_2) = self.basic_mul(other_ct);

        self.relinearization_1(c_0, c_1, c_2, rlk_1)
    }
}

/// Multiply two ciphertexts, using Relinearization Version 2.
/// Since multiplication requires a relinearization key, you must multiply a ciphertext
/// with a tuple of (Ciphertext, &RelinearizationKey2). The type of the relinearization
/// key determines whether the multiplication uses Relinearization Version 1 or 2.
///
/// ```rust
/// # extern crate rand;
/// # use rand::SeedableRng;
/// #
/// # extern crate bfv;
/// # use bfv::{SecretKey, Plaintext};
/// #
/// # let t = 12;         // Plaintext modulus
/// # let q = 65536;      // Ciphertext modulus
/// # let std_dev = 3.2;  // Standard deviation for generating the error
/// # let degree = 4;     // Degree of polynomials used for encoding and encrypting messages
/// #
/// # // Generate a seeded RNG. Any Rng that imlements RngCore + CryptoRng can be used.
/// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
/// #
/// let secret_key = SecretKey::generate(degree, &mut rng);
/// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
///
/// // p = the amount to scale the modulus, during modulus switching
/// // Technically p should be >= q^3 for security (see paper discussion on Relinearization Version 2),
/// // but setting p = q^3 results in an overflow when taking p * q so we will test with a smaller p.
/// let p = 2_i64.pow(13) * q;
/// let rlk_2 = secret_key.relin_key_gen_2(q, std_dev, &mut rng, p);
///
/// let pt_1 = Plaintext::rand(degree, t, &mut rng);
/// let pt_2 = Plaintext::rand(degree, t, &mut rng);
/// let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
/// let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
///
/// // Multiply the ciphertexts: ct_1 * ct_2
/// let mul_ct = ct_1 * (ct_2, &rlk_2);
///
/// // Decrypt the result of the multiplication
/// let mul_pt = mul_ct.decrypt(&secret_key);
///
/// // Compare the expected output to the decrypted output
/// let expected_pt = (pt_1.poly() * pt_2.poly()) % (t, degree);
/// assert_eq!(mul_pt.poly(), expected_pt)
/// ```
impl Mul<(Ciphertext, &RelinearizationKey2)> for Ciphertext {
    type Output = Self;
    fn mul(self, other: (Ciphertext, &RelinearizationKey2)) -> Self::Output {
        let (other_ct, rlk_2) = other;

        let (c_0, c_1, c_2) = self.basic_mul(other_ct);

        self.relinearization_2(c_0, c_1, c_2, rlk_2)
    }
}
