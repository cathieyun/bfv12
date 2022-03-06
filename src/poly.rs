use std::ops::{Add, Mul, Neg, Sub};

#[derive(Clone, Debug)]
pub struct Poly {
    pub val: Vec<i64>,
    pub dimension: usize,
    pub q: i64,
}

/// TODO(cathie): also implement over &Poly, so we don't have to do unnecessary cloning.

impl Add<Poly> for Poly {
    type Output = Poly;
    fn add(self, other: Poly) -> Self::Output {
        assert!(
            self.dimension == other.dimension,
            "Polynomial dimensions are not equal"
        );
        assert!(self.q == other.q, "Polynomial moduli are not equal");
        let q = self.q;

        let out_val = self
            .val
            .into_iter()
            .zip(other.val.iter())
            .map(|(self_i, other_i)| (self_i + other_i) % q)
            .collect();
        Poly {
            val: out_val,
            dimension: self.dimension,
            q,
        }
    }
}

impl Sub<Poly> for Poly {
    type Output = Poly;
    fn sub(self, other: Poly) -> Self::Output {
        assert!(
            self.dimension == other.dimension,
            "Polynomial dimensions are not equal"
        );
        assert!(self.q == other.q, "Polynomial moduli are not equal");
        let q = self.q;

        let out_val = self
            .val
            .into_iter()
            .zip(other.val.iter())
            .map(|(self_i, other_i)| (self_i - other_i) % q)
            .collect();
        Poly {
            val: out_val,
            dimension: self.dimension,
            q,
        }
    }
}

impl Neg for Poly {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        for v in self.val.iter_mut() {
            *v = -*v
        }
        self
    }
}

impl Mul<Poly> for Poly {
    type Output = Poly;
    fn mul(self, other: Poly) -> Self::Output {
        assert!(
            self.dimension == other.dimension,
            "Polynomial dimensions are not equal"
        );
        assert!(self.q == other.q, "Polynomial moduli are not equal");

        let mut out_val = vec![0; self.dimension];
        let degree = self.dimension - 1;
        let q = self.q;

        for (i, self_i) in self.val.iter().enumerate() {
            for (j, other_j) in other.val.iter().enumerate() {
                let target_degree = i + j;

                // If the resulting coefficient is of degree <= N, add it to the output poly directly.
                if target_degree <= degree {
                    out_val[target_degree] = (out_val[target_degree] + self_i * other_j) % q;
                }
                // If the resulting coefficient is of degree >N, it wraps around (mod X^N + 1)
                // so take the degree mod N, and subtract it from the output poly
                else {
                    out_val[target_degree % (degree + 1)] =
                        (out_val[target_degree % (degree + 1)] - self_i * other_j) % q;
                }
            }
        }
        Poly {
            val: out_val,
            dimension: self.dimension,
            q,
        }
    }
}

impl Mul<i64> for Poly {
    type Output = Poly;
    fn mul(self, other: i64) -> Self::Output {
        let q = self.q;
        let out_val = self
            .val
            .into_iter()
            .map(|self_i| (self_i * other) % q)
            .collect();
        Poly {
            val: out_val,
            dimension: self.dimension,
            q,
        }
    }
}

// Multiply by a float (f64) and taking the result mod q, rounding to the nearest integer.
impl Mul<f64> for Poly {
    type Output = Poly;
    fn mul(self, other: f64) -> Self::Output {
        let q = self.q;
        let out_val = self
            .val
            .into_iter()
            .map(|self_i| (self_i as f64 * other).round() as i64 % q)
            .collect();
        Poly {
            val: out_val,
            dimension: self.dimension,
            q,
        }
    }
}

impl Poly {
    // Take polynomial mod t, for converting to the signed plaintext space
    pub fn _modulo(mut self, modulus: i64) -> Poly {
        for v in self.val.iter_mut() {
            *v = *v % modulus
        }
        self
    }

    // Add t to the polynomial and then take mod t, for converting to the unsigned plaintext space
    pub fn unsigned_modulo(mut self, modulus: i64) -> Poly {
        for v in self.val.iter_mut() {
            *v = (*v + modulus) % modulus
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::poly::Poly;

    fn a_poly() -> Poly {
        Poly {
            val: vec![-7, 0, 0, 3, -1, 6, -3, 5, 9, -5],
            dimension: 10,
            q: 256,
        }
    }
    fn b_poly() -> Poly {
        Poly {
            val: vec![-1, -1, 0, 1, 0, -1, 1, 1, -1, -1],
            dimension: 10,
            q: 256,
        }
    }

    #[test]
    fn add_test() {
        let a = a_poly();
        let b = b_poly();
        let sum = a + b;
        println!("sum: {:?}", sum.val);
        assert_eq!(sum.val, vec![-8, -1, 0, 4, -1, 5, -2, 6, 8, -6]);
        assert_eq!(sum.dimension, 10);
        assert_eq!(sum.q, 256);
    }

    #[test]
    fn sub_test() {
        let a = a_poly();
        let b = b_poly();
        let sub = a - b;
        assert_eq!(sub.val, vec![-6, 1, 0, 2, -1, 7, -4, 4, 10, -4]);
        assert_eq!(sub.dimension, 10);
        assert_eq!(sub.q, 256);
    }

    #[test]
    fn neg_test() {
        let a = a_poly();
        let neg = -a;
        assert_eq!(neg.val, vec![7, 0, 0, -3, 1, -6, 3, -5, -9, 5]);
        assert_eq!(neg.dimension, 10);
        assert_eq!(neg.q, 256);
    }

    #[test]
    fn mul_poly_test() {
        let a = Poly {
            val: vec![4, 5, 0],
            dimension: 3,
            q: 256,
        };
        let b = Poly {
            val: vec![7, 9, 0],
            dimension: 3,
            q: 256,
        };
        let mul = a * b;
        assert_eq!(mul.val, vec![28, 71, 45]);
    }

    #[test]
    fn mul_const_i64_test() {
        let a = a_poly();
        let mul = a * 17;
        assert_eq!(mul.val, vec![-119, 0, 0, 51, -17, 102, -51, 85, 153, -85]);
    }

    #[test]
    fn mul_const_f64_test() {
        let a = a_poly();
        let mul = a * 3.7;
        assert_eq!(mul.val, vec![-26, 0, 0, 11, -4, 22, -11, 19, 33, -19]);
    }

    #[test]
    fn modulo_test() {
        let a = a_poly();
        let modulo = a._modulo(4);
        assert_eq!(modulo.val, vec![-3, 0, 0, 3, -1, 2, -3, 1, 1, -1]);
    }

    #[test]
    fn unsigned_modulo_test() {
        let a = a_poly();
        let pos = a.unsigned_modulo(64);
        assert_eq!(pos.val, vec![57, 0, 0, 3, 63, 6, 61, 5, 9, 59])
    }
}
