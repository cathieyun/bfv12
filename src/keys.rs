use super::poly::Poly;
use super::random_source;
use rand::{CryptoRng, RngCore};

/// A BFV12 Secret Key
#[derive(Clone, Debug)]
pub struct SecretKey {
    ///`s <- R_2`
    pub(crate) poly: Poly,
}

/// A BFV12 Public Key
///
/// * `p_0` = `[-(a * s + e)]_q`
/// * `p_1` = `a`
/// * `q` = ciphertext modulus
#[derive(Clone, Debug)]
pub struct PublicKey {
    pub(crate) p_0: Poly,
    pub(crate) p_1: Poly,
    pub(crate) q: i64,
}

/// A BFV12 Relinearization Key, Version 1
///
/// * `val` = `[ ( [-(a_i * s + e_i) + T^i * s^2]_q, a_i) : i \in (0..l)]`
/// * `T` = the decomposition base used for relinearization
/// * `l` = `floor(log_t(q))`, the number of levels to decompose
#[derive(Clone, Debug)]
pub struct RelinearizationKey1 {
    pub(crate) val: Vec<(Poly, Poly)>,
    pub(crate) base: i64,
    pub(crate) l: usize,
}

/// A BFV12 Relinearization Key, Version 2
///
/// * `rlk_0` = `([-(a * s + e) + p * s^2]_{p*q})`
/// * `rlk_1` = `a`
/// * `p` = the amount to scale the modulus, during modulus switching
#[derive(Clone, Debug)]
pub struct RelinearizationKey2 {
    pub(crate) rlk_0: Poly,
    pub(crate) rlk_1: Poly,
    pub(crate) p: i64,
}

impl SecretKey {
    /// Generate a secret key by sampling the coefficients of s uniformly
    /// from R_2, which in this implementation is the set {0, 1}.
    ///
    /// * `degree`: the polynomial degree of the secret key
    /// * `rng`: the RNG used to generate randomness
    ///
    /// ```rust
    /// # use rand::SeedableRng;
    /// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
    /// #
    /// use bfv12::SecretKey;
    ///
    /// let degree = 4;
    /// let secret_key = SecretKey::generate(degree, &mut rng);
    /// ```
    pub fn generate<T: RngCore + CryptoRng>(degree: usize, rng: &mut T) -> SecretKey {
        SecretKey {
            poly: random_source::get_uniform(2, degree, rng),
        }
    }

    /// Generate a public key from a secret key.
    ///
    /// * `q`: the ciphertext modulus
    /// * `std_dev`: the standard deviation for error generation
    /// * `rng`: the RNG used to generate randomness
    ///
    /// ```rust
    /// # use rand::SeedableRng;
    /// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
    /// #
    /// use bfv12::SecretKey;
    ///
    /// let degree = 4;
    /// let std_dev = 3.2;
    /// let q = 65536;
    ///
    /// let secret_key = SecretKey::generate(degree, &mut rng);
    /// let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
    /// ```
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
        let p_0 = (-(a.clone() * s.clone() + e)) % (q, degree);

        PublicKey { p_0, p_1, q }
    }

    /// Generate a relinearization key, using the approach in Version 1
    ///
    /// * `q`: the ciphertext modulus
    /// * `std_dev`: the standard deviation for error generation
    /// * `rng`: the RNG used to generate randomness
    /// * `base`: the decomposition base used for relinearization
    ///
    /// Note on base selection:
    /// The base can be chosen to trade off relinearisation time and space, for error accumulation.
    /// The larger the base, the larger the error. The bounds on the base are discussed in the paper.
    /// Choosing T = ceil(sqrt(q)) will minimize relinearisation time and space, at the expense of error.
    /// Choosing T = log_2(q) will decrease error at the cost of relinearisation time and space.
    ///
    /// ```rust
    /// # use rand::SeedableRng;
    /// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
    /// #
    /// use bfv12::SecretKey;
    ///
    /// let degree = 4;
    /// let std_dev = 3.2;
    /// let q = 65536;
    /// let rlk_base = (q as f64).log2() as i64;
    ///
    /// let secret_key = SecretKey::generate(degree, &mut rng);
    /// let relin_key_1 = secret_key.relin_key_gen_1(q, std_dev, &mut rng, rlk_base);
    /// ```
    pub fn relin_key_gen_1<T: RngCore + CryptoRng>(
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
                let rlk_i = rlk_i_raw % (q, degree);
                (rlk_i, a_i)
            })
            .collect();
        RelinearizationKey1 { val, base, l }
    }

    /// Generate a relinearization key, using the approach in Version 2
    /// * `q`: the ciphertext modulus
    /// * `std_dev`: the standard deviation for error generation
    /// * `rng`: the RNG used to generate randomness
    /// * `p`: the amount to scale the modulus, during modulus switching
    ///
    /// Note on p selection:
    /// Technically p needs to be >= q^3 for security (see paper discussion on Relinearization Version 2),
    /// However, setting p = q^3 results in an overflow when taking p * q.
    /// Therefore, in this library we will test with a smaller p, and recommend using Relinearization Version 1.
    ///
    /// ```rust
    /// # use rand::SeedableRng;
    /// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
    /// #
    /// use bfv12::SecretKey;
    ///
    /// let degree = 4;
    /// let std_dev = 3.2;
    /// let q = 65536;
    /// let p = 2_i64.pow(13) * q;
    ///
    /// let secret_key = SecretKey::generate(degree, &mut rng);
    /// let relin_key_2 = secret_key.relin_key_gen_2(q, std_dev, &mut rng, p);
    /// ```
    pub fn relin_key_gen_2<T: RngCore + CryptoRng>(
        &self,
        q: i64,
        std_dev: f64,
        rng: &mut T,
        p: i64,
    ) -> RelinearizationKey2 {
        let degree = self.poly.degree();
        let s = self.poly.clone();

        let a = random_source::get_uniform(p * q, degree, rng);
        let e = random_source::get_gaussian(std_dev, degree, rng);
        let rlk_0 = (-(a.clone() * s.clone() + e) + s.clone() * s.clone() * p) % (p * q, degree);

        RelinearizationKey2 { rlk_0, rlk_1: a, p }
    }
}
