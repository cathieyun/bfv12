fn main() {
    let mut count = 0;
    for _ in 0..1000 {
        let q = 65536;
        let t = 12;
        let std_dev = 3.2;
        let degree = 4;
        let rlk_base = (q as f64).log2() as i64;

        let mut rng = rand::thread_rng();

        let secret_key = SecretKey::generate(degree, &mut rng);
        let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
        let rlk_1 = secret_key.relinearization_key_gen_1(q, std_dev, &mut rng, rlk_base);

        let pt_1 = Plaintext::rand(degree, t, q, &mut rng);
        let pt_2 = Plaintext::rand(degree, t, q, &mut rng);
        let pt_3 = Plaintext::rand(degree, t, q, &mut rng);
        let pt_4 = Plaintext::rand(degree, t, q, &mut rng);

        let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
        let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
        let ct_3 = pt_3.encrypt(&public_key, std_dev, &mut rng);
        let ct_4 = pt_4.encrypt(&public_key, std_dev, &mut rng);

        let expr_ct = ct_1.mul_1(ct_2, &rlk_1) + ct_3.mul_1(ct_4, &rlk_1);
        let expr_pt = expr_ct.decrypt(&secret_key);

        let expected_pt = (pt_1.poly.clone() * pt_2.poly.clone()
            + pt_3.poly.clone() * pt_4.poly.clone())
        .modulo(t, degree);
        if expr_pt.poly == expected_pt {
            println!(
                "success: {:?} * {:?} + {:?} * {:?} = {:?}",
                pt_1.poly, pt_2.poly, pt_3.poly, pt_4.poly, expr_pt.poly
            );
            count += 1;
        }
    }

    println!("succeeded {:?}/1000 times", count);
}

mod ciphertext;
mod keys;
mod plaintext;
mod poly;
mod random_source;
mod tests;

pub use ciphertext::Ciphertext;
pub use keys::{PublicKey, RelinearizationKey1, SecretKey};
pub use plaintext::Plaintext;
