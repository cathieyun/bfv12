use rand::distributions::{Distribution, Normal, Uniform};
use super::poly::Poly;

/// Gets the discrete Gaussian distribution D_{Z, sigma} centered over 0.
/// Returns a dimension-length vector of gaussian samples.
pub fn get_gaussian(std_dev: f64, dimension: usize, modulus: i64) -> Poly {
    let gaussian = Normal::new(0.0, std_dev);

    // TODO(cathie): allow source to be generic over any rng impl, so we can use a seeded rng for
    // deterministic testing and a cryptographic RNG otherwise. 
    let mut rng = rand::thread_rng();
    let val: Vec<i64> = (0..dimension).map(|_| gaussian.sample(&mut rng) as i64).collect();
    Poly { val, dimension, modulus }
}

/// Returns a dimension-length vector of values sampled uniformly from [-bound/2, bound/2].
/// TODO(cathie): handle cases where bound/2 is not an integer: sample from ceil(-bound/2) to floor(bound/2).
/// Note: bound and modulus can be different if sampling from {-1, 0, 1} such as for the secret key.
pub fn get_uniform(bound: i64, dimension: usize, modulus: i64) -> Poly {
    let between = Uniform::new_inclusive(-bound/2, bound/2);
    let mut rng = rand::thread_rng();

    let val: Vec<i64> = (0..dimension).map(|_| between.sample(&mut rng)).collect();
    Poly { val, dimension, modulus }
}
