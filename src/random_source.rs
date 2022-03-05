use probability::distribution::{Gaussian, Uniform, Sample};
use probability::prelude::source;

/// Gets the discrete Gaussian distribution D_{Z, sigma} centered over 0.
/// Returns a dimension-length vector of gaussian samples.
pub fn get_gaussian(std_dev: f64, dimension: usize) -> Vec<i64> {
    let gaussian = Gaussian::new(0.0, std_dev);
    // TODO(cathie): allow source to be generic over any rng impl, so we can use a seeded rng for
    // deterministic testing and a cryptographic RNG otherwise. 
    let mut source = source::default();
    let val: Vec<i64> = (0..dimension).map(|_| gaussian.sample(&mut source) as i64).collect();
    val
}

/// Returns a dimension-length vector of values sampled uniformly from [-q/2, q/2).
pub fn get_uniform(q: u64, dimension: usize) -> Vec<i64> {
    let uniform = Uniform::new(-(q as f64)/2.0, (q as f64)/2.0);
    let mut source = source::default();
    let val: Vec<i64> = (0..dimension).map(|_| uniform.sample(&mut source) as i64).collect();
    val
}
