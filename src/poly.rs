use std::cmp;
use std::ops::{Add, Mul, Neg, Sub, Div, Rem};

#[derive(Clone, Debug, PartialEq)]
pub struct Poly(Vec<i64>);

/// TODO(cathie): also implement ops over &Poly, so we don't have to do unnecessary cloning.
/// TODO(cathie): also implement Sum, so we can sum over an iterator of Polys.
/// TODO(cathie): implement pretty print for polynomials

impl Add<Poly> for Poly {
    type Output = Poly;
    fn add(self, other: Poly) -> Self::Output {
        let max_degree = cmp::max(self.degree(), other.degree());

        let out_val = (0..max_degree)
            .map(|i| {
                let self_i = if i < self.degree() { self.0[i] } else { 0 };
                let other_i = if i < other.degree() { other.0[i] } else { 0 };
                self_i + other_i
            })
            .collect();
        Poly(out_val)
    }
}

impl Sub<Poly> for Poly {
    type Output = Poly;
    fn sub(self, other: Poly) -> Self::Output {
        let max_degree = cmp::max(self.degree(), other.degree());

        let out_val = (0..max_degree)
            .map(|i| {
                let self_i = if i < self.degree() { self.0[i] } else { 0 };
                let other_i = if i < other.degree() { other.0[i] } else { 0 };
                self_i - other_i
            })
            .collect();
        Poly(out_val)
    }
}

impl Neg for Poly {
    type Output = Self;
    fn neg(mut self) -> Self::Output {
        for v in self.0.iter_mut() {
            *v = -*v;
        }
        self
    }
}

impl Mul<i64> for Poly {
    type Output = Poly;
    fn mul(self, other: i64) -> Self::Output {
        let out_val = self.0.into_iter().map(|self_i| self_i * other).collect();
        Poly(out_val)
    }
}

// Multiply by a float (f64) and round to the nearest integer.
impl Mul<f64> for Poly {
    type Output = Poly;
    fn mul(self, other: f64) -> Self::Output {
        let out_val = self
            .0
            .into_iter()
            .map(|self_i| (self_i as f64 * other).round() as i64)
            .collect();
        Poly(out_val)
    }
}

// Divide by a float (f64) and round to the nearest integer.
impl Div<f64> for Poly {
    type Output = Poly;
    fn div(self, other: f64) -> Self::Output {
        let other_inv = 1.0 / other;
        self * other_inv
    }
}

impl Mul<Poly> for Poly {
    type Output = Poly;
    fn mul(self, other: Poly) -> Self::Output {
        let mut out_val = vec![0; self.0.len() + other.0.len() - 1];
        for (i, self_i) in self.0.iter().enumerate() {
            for (j, other_j) in other.0.iter().enumerate() {
                let target_degree = i + j;
                out_val[target_degree] += self_i * other_j;
            }
        }
        Poly(out_val)
    }
}

impl Rem<(i64, usize)> for Poly {
    type Output = Poly;
    fn rem(self, modulus: (i64, usize)) -> Self::Output {
        let coeff_mod = modulus.0;
        let degree = modulus.1;
        let mut out_val = vec![0; degree];

        // Take the polynomial mod (X^N + 1).
        // 1. After a multiplication by X^{2N}, the polynomial is unchanged mod (X^N + 1).
        //    Therefore, we can take the degree % 2N.
        // 2. If degree % 2N > N, the coefficients should be negated and added to the degree % N.
        // 3. If degree % 2N <= N, the coefficients should be added to the degree % 2N.
        for (i, coeff) in self.0.iter().enumerate() {
            // $ X^i == X^{i + j * 2N} mod (X^N + 1) for all j $
            // So we can take the coeff degree mod 2N.
            let reduced_i = i % (2 * degree);
            if reduced_i >= degree {
                out_val[reduced_i % degree] -= coeff;
            } else {
                out_val[reduced_i] += coeff;
            }
        }

        // Take each coefficient % coeff_mod
        for coeff in out_val.iter_mut() {
            *coeff = Poly::mod_coeff(*coeff, coeff_mod)
        }
        Poly(out_val)
    }
}

impl Poly {
    pub fn new(val: Vec<i64>) -> Poly {
        Poly(val)
    }

    pub fn degree(&self) -> usize {
        self.0.len()
    }

    // Reduce a coefficient into the [-q/2, q/2) bounds.
    fn mod_coeff(coeff: i64, q: i64) -> i64 {
        // If we are working in [-q/2, q/2):
        // if coeff >= q/2 {
        //     return ((coeff + q/2) % q) - q/2;
        // } else if coeff < -q/2 {
        //     return ((coeff - q/2) % q) + q/2;
        // }
        // coeff

        // If we are working in in [0, q):
        (coeff % q + q) % q
    }

    // Decompose a polynomial to l levels, with each level base T, such that:
    // $ poly = sum_{i=0}^l poly^(i) T^i $ with $ poly^(i) \in R_T $
    pub fn decompose(self, l: usize, base: i64) -> Vec<Poly> {
        let mut mut_poly = self.clone();

        // Iterate i: from highest to lowest level, starting with l
        let out_polys: Vec<Poly> = (0..l)
            .rev()
            .map(|i| {
                // T^i, which is the multiplier for that level i
                let base_i = base.pow(i as u32);

                // Iterate j: through the coefficients in poly, to decompose for level i
                let dec_val_i: Vec<i64> = mut_poly
                    .0
                    .iter_mut()
                    .map(|val_j| {
                        // Calculate how many times T^i divides the coefficient, to get decomposition
                        let fl_div = *val_j as f64 / base_i as f64;
                        let int_div = if fl_div > 0.0 {
                            fl_div.floor()
                        } else {
                            fl_div.ceil()
                        } as i64;
                        // Update the coefficient by subtracting T^i * the decomposed value
                        *val_j = *val_j - base_i * int_div;
                        // Return the decomposed value for that coefficient for level i
                        int_div
                    })
                    .collect();
                Poly(dec_val_i)
            })
            .collect();
        // We can't reverse within the original expression because the two "rev" calls cancel each other out
        // and we get the wrong decomposition answer (decomposing starting from the smallest levels).
        out_polys.into_iter().rev().collect()
    }
    /*
    fn _decompose_i64(val: i64, l: i64, base: i64) -> Vec<i64> {
        let mut mut_val = val.clone();
        let out: Vec<i64> = (0..l)
            .rev()
            .map(|i| {
                let base_i = base.pow(i as u32);
                // Calcualte how many times base^i divides the value
                let fl_div = (mut_val as f64) / (base_i as f64);
                let int_div = if fl_div > 0.0 {
                    fl_div.floor()
                } else {
                    fl_div.ceil()
                } as i64;
                mut_val -= int_div * base_i;
                int_div
            })
            .collect();
        // We can't reverse within the original expression because the two "rev" calls cancel each other out
        // and we get the wrong decomposition answer (decomposing starting from the smallest levels).
        out.into_iter().rev().collect()
    }*/
}

#[cfg(test)]
mod tests {
    use crate::poly::Poly;

    fn a_poly() -> Poly {
        Poly(vec![-7, 0, 0, 3, -1, 6, -3, 5, 9, -5])
    }
    fn b_poly() -> Poly {
        Poly(vec![-1, -1, 0, 1, 0, -1, 1, 1, -1, -1])
    }

    #[test]
    fn add_test() {
        let a = a_poly();
        let b = b_poly();
        let sum = a + b;
        assert_eq!(sum.0, vec![-8, -1, 0, 4, -1, 5, -2, 6, 8, -6]);

        // Test that vector addition still works with uneven vector lengths
        let c = Poly(vec![3, -1, 6, -3]);
        let sum_uneven = c + sum;
        assert_eq!(sum_uneven.0, vec![-5, -2, 6, 1, -1, 5, -2, 6, 8, -6]);
    }

    #[test]
    fn sub_test() {
        let a = a_poly();
        let b = b_poly();
        let sub = a - b;
        assert_eq!(sub.0, vec![-6, 1, 0, 2, -1, 7, -4, 4, 10, -4]);

        // Test that vector subtraction still works with uneven vector lengths
        let c = Poly(vec![3, -1, 6, -3]);
        let sub_uneven = c - sub;
        assert_eq!(sub_uneven.0, vec![9, -2, 6, -5, 1, -7, 4, -4, -10, 4]);
    }

    #[test]
    fn neg_test() {
        let a = a_poly();
        let neg = -a;
        assert_eq!(neg.0, vec![7, 0, 0, -3, 1, -6, 3, -5, -9, 5]);
    }

    #[test]
    fn mul_const_i64_test() {
        let a = a_poly();
        let mul = a * 17;
        assert_eq!(mul.0, vec![-119, 0, 0, 51, -17, 102, -51, 85, 153, -85]);
    }

    #[test]
    fn mul_const_f64_test() {
        let a = a_poly();
        let mul = a * 3.7;
        assert_eq!(mul.0, vec![-26, 0, 0, 11, -4, 22, -11, 19, 33, -19]);
    }

    #[test]
    fn mul_poly_test() {
        let a = Poly(vec![4, 5, 2]);
        let b = Poly(vec![7, 9, 1]);
        let mul = a * b;
        assert_eq!(mul.0, vec![28, 71, 63, 23, 2]);
    }

    #[test]
    fn poly_modulo_test() {
        let a = a_poly();
        let b = b_poly();
        let mul = a * b;
        assert_eq!(
            mul.0,
            vec![7, 7, 0, -10, -2, 2, -7, -10, -4, 4, 6, 14, -9, -12, 16, 2, -19, -4, 5]
        );
        let mod_degree_2 = mul.clone() % (16, 2);
        assert_eq!(mod_degree_2.0, vec![1, 1]);
        let mod_degree_4 = mul.clone() % (16, 4);
        assert_eq!(mod_degree_4.0, vec![11, 1, 2, 12]);
        let mod_degree_8 = mul.clone() % (16, 8);
        assert_eq!(mod_degree_8.0, vec![8, 15, 15, 8, 7, 14, 9, 4]);
        let mod_degree_16 = mul.clone() % (16, 16);
        assert_eq!(
            mod_degree_16.0,
            vec![10, 11, 11, 6, 14, 2, 9, 6, 12, 4, 6, 14, 7, 4, 0, 2]
        );
    }

    #[test]
    fn coeff_modulo_test() {
        let a = a_poly();
        let modulo = a % (4, 10);
        assert_eq!(modulo.0, vec![1, 0, 0, 3, 3, 2, 1, 1, 1, 3]);
    }

    #[test]
    fn decomposition_test() {
        let a = a_poly();
        let dec = a.clone().decompose(4, 2);

        assert_eq!(dec[0].0, vec![-1, 0, 0, 1, -1, 0, -1, 1, 1, -1]);
        assert_eq!(dec[1].0, vec![-1, 0, 0, 1, 0, 1, -1, 0, 0, 0]);
        assert_eq!(dec[2].0, vec![-1, 0, 0, 0, 0, 1, 0, 1, 0, -1]);
        assert_eq!(dec[3].0, vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 0]);

        let recomposed =
            dec[0].clone() + dec[1].clone() * 2 + dec[2].clone() * 4 + dec[3].clone() * 8;
        assert_eq!(recomposed, a);
    }
}
