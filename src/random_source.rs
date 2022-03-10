use super::poly::Poly;
use rand::distributions::{Distribution, Normal, Uniform};
use rand::{CryptoRng, RngCore};

/// Gets the discrete Gaussian distribution D_{Z, sigma} centered over 0, and take the absolute value.
/// Returns a dimension-length vector of gaussian samples.
pub fn get_gaussian<T: RngCore + CryptoRng>(std_dev: f64, dimension: usize, rng: &mut T) -> Poly {
    let gaussian = Normal::new(0.0, std_dev);
    let val: Vec<i64> = (0..dimension)
        .map(|_| gaussian.sample(rng).abs() as i64)
        .collect();
    Poly::new(val)
}

/// Returns a dimension-length vector of values sampled uniformly from [0, bound).
pub fn get_uniform<T: RngCore + CryptoRng>(bound: i64, dimension: usize, rng: &mut T) -> Poly {
    let between = Uniform::new(0, bound);

    let val: Vec<i64> = (0..dimension).map(|_| between.sample(rng)).collect();
    Poly::new(val)
}
