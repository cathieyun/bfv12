use std::ops::{Add, Mul, Neg, Sub};

#[derive(Clone, Debug)]
pub struct Poly {
    pub val: Vec<i64>,
    pub dimension: usize,
    pub modulus: i64,
}

impl Add<Poly> for Poly {
    type Output = Poly;
    fn add(self, other: Poly) -> Self::Output{
        assert!(self.dimension == other.dimension, "Polynomial dimensions are not equal");
        assert!(self.modulus == other.modulus, "Polynomial moduli are not equal");
        let q = self.modulus;

        let out_val = self.val.into_iter()
                              .zip(other.val.iter())
                              .map(|(self_i, other_i)| (self_i + other_i) % q)
                              .collect();
        Poly {
            val: out_val,
            dimension: self.dimension,
            modulus: self.modulus,
        }
    }
}

impl Sub<Poly> for Poly {
    type Output = Poly;
    fn sub(self, other: Poly) -> Self::Output{
        assert!(self.dimension == other.dimension, "Polynomial dimensions are not equal");
        assert!(self.modulus == other.modulus, "Polynomial moduli are not equal");
        let q = self.modulus;

        let out_val = self.val.into_iter()
                              .zip(other.val.iter())
                              .map(|(self_i, other_i)| (self_i - other_i) % q)
                              .collect();
        Poly {
            val: out_val,
            dimension: self.dimension,
            modulus: self.modulus,
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
        assert!(self.dimension == other.dimension, "Polynomial dimensions are not equal");
        assert!(self.modulus == other.modulus, "Polynomial moduli are not equal");

        let mut out_val = vec![0; self.dimension];
        let q = self.modulus as i64;
        let degree = self.dimension - 1;

        for (i, self_i) in self.val.iter().enumerate() {
            for (j, other_j) in other.val.iter().enumerate() {
                let target_degree = i + j;

                // If the resulting coefficient is of degree <= N, add it to the output poly directly.
                if target_degree <= degree {
                    out_val[target_degree] += self_i * other_j % q;
                }
                // If the resulting coefficient is of degree >N, it wraps around (mod X^N + 1)
                // so take the degree mod N, and subtract it from the output poly
                else {
                    out_val[target_degree % (degree + 1)] -= self_i * other_j % q;
                }
            }
        }
        Poly {
            val: out_val,
            dimension: self.dimension,
            modulus: self.modulus,
        }
    }
}

mod tests {
    use crate::poly::Poly;

    fn a_poly() -> Poly {
        Poly {
            val: vec![-7, 0, 0, 3, -1, 6, -3, 5, 9, -5],
            dimension: 10,
            modulus: 256,
        }
    }
    fn b_poly() -> Poly {
        Poly {
            val: vec![-1, -1, 0, 1, 0, -1, 1, 1, -1, -1],
            dimension: 10,
            modulus: 256,
        }
    }

    #[test]
    fn add_test() {
        let a = a_poly();
        let b = b_poly();
        let sum = a + b;
        println!("sum: {:?}", sum.val);
        assert!(sum.val == vec![-8, -1, 0, 4, -1, 5, -2, 6, 8, -6]);
        assert!(sum.dimension == 10);
        assert!(sum.modulus == 256);
    }

    #[test]
    fn sub_test() {
        let a = a_poly();
        let b = b_poly();
        let sub = a - b;
        assert!(sub.val == vec![-6, 1, 0, 2, -1, 7, -4, 4, 10, -4]);
        assert!(sub.dimension == 10);
        assert!(sub.modulus == 256);
    }

    #[test]
    fn neg_test() {
        let a = a_poly();
        let neg = -a;
        assert!(neg.val == vec![7, 0, 0, -3, 1, -6, 3, -5, -9, 5]);
        assert!(neg.dimension == 10);
        assert!(neg.modulus == 256);
    }

    #[test]
    fn mul_test() {
        let a = Poly {
            val: vec![4, 5, 0],
            dimension: 3,
            modulus: 256,
        };
        let b = Poly {
            val: vec![7, 9, 0],
            dimension: 3,
            modulus: 256,
        };
        let mul = a * b;
        assert!(mul.val == vec![28, 71, 45]);
    }
}