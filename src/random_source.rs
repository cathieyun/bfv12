use super::poly::Poly;
use rand::distributions::{Distribution, Normal, Uniform};
use rand::{CryptoRng, RngCore};

/// Gets the discrete Gaussian distribution D_{Z, sigma} centered over 0.
/// Returns a dimension-length vector of gaussian samples.
pub fn get_gaussian<T: RngCore + CryptoRng>(std_dev: f64, dimension: usize, rng: &mut T) -> Poly {
    let gaussian = Normal::new(0.0, std_dev);
    // If we are working in [-q/2, q/2):
    // let val: Vec<i64> = (0..dimension)
    //     .map(|_| gaussian.sample(rng).round() as i64)
    //     .collect();

    // If we are working in in [0, q):
    let val: Vec<i64> = (0..dimension)
        .map(|_| gaussian.sample(rng).abs() as i64)
        .collect();
    Poly::new(val)
}

/// Returns a dimension-length vector of values sampled uniformly from [-bound/2, bound/2].
/// Note: bound and modulus can be different if sampling from {-1, 0, 1}, such as for the secret key.
pub fn get_uniform<T: RngCore + CryptoRng>(bound: i64, dimension: usize, rng: &mut T) -> Poly {
    // If we are working in [-q/2, q/2):
    // let lower = (-bound as f64 / 2.0).ceil() as i64;
    // let upper = (bound as f64 / 2.0).floor() as i64;
    // let between = Uniform::new(lower, upper);

    // If we are working in in [0, q):
    let between = Uniform::new(0, bound);

    let val: Vec<i64> = (0..dimension).map(|_| between.sample(rng)).collect();
    Poly::new(val)
}
