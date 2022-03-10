use super::ciphertext::Ciphertext;
use super::keys::PublicKey;
use super::poly::Poly;
use super::random_source;
use rand::{CryptoRng, RngCore};

/// A BFV12 Plaintext (an encoded message)
#[derive(Debug, PartialEq)]
pub struct Plaintext {
    /// The polynomial representing the list of plaintext values
    poly: Poly,
    /// The modulus of the plaintext space
    t: i64,
}

impl Plaintext {
    /// Instantiate a new Plaintext
    ///
    /// * `poly`: the polynomial set to the input vector
    /// * `t`: the plaintext modulus
    ///
    /// ```rust
    /// use bfv::Plaintext;
    /// let pt = Plaintext::new(vec![0, 1, 2, 3], 4);
    /// ```
    pub fn new(val: Vec<i64>, t: i64) -> Plaintext {
        Plaintext::new_from_poly(Poly::new(val), t)
    }

    pub(crate) fn new_from_poly(poly: Poly, t: i64) -> Plaintext {
        // The plaintext space is taken as R_t for some integer t > 1.
        assert!(t > 1);
        Plaintext { poly, t }
    }

    /// Instantiate a new random Plaintext uniformly over [0, t) with length `degree`
    ///
    /// * `degree`: the degree (length) of the newly generated plaintext
    /// * `t`: the plaintext modulus
    /// # `rng`: the RNG used to generate randomness. Any Rng that imlements RngCore + CryptoRng can be used.
    ///
    /// ```rust
    /// # extern crate rand;
    /// # use rand::SeedableRng;
    /// # let mut rng = rand::rngs::StdRng::seed_from_u64(18);
    /// #
    /// use bfv::Plaintext;
    /// let rand_pt = Plaintext::rand(10, 4, &mut rng);
    /// ```
    pub fn rand<T: RngCore + CryptoRng>(degree: usize, t: i64, rng: &mut T) -> Plaintext {
        assert!(t > 1);
        Plaintext {
            poly: random_source::get_uniform(t, degree, rng),
            t,
        }
    }

    pub fn poly(&self) -> Poly {
        self.poly.clone()
    }

    /// Encrypt a plaintext with a given public key
    ///
    /// * `pub_key`: the public key used to encrypt plaintext
    /// * `std_dev`: the standard deviation used for generating the error in the encryption
    /// # `rng`: the RNG used to generate randomness. Any Rng that imlements RngCore + CryptoRng can be used.
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
    /// ```
    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        pub_key: &PublicKey,
        std_dev: f64,
        rng: &mut T,
    ) -> Ciphertext {
        assert_eq!(self.poly.degree(), pub_key.p_0.degree());
        let q = pub_key.q;
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
            q,
            t: self.t,
        }
    }
}
