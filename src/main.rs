fn main() {
    let t = 4;
    let q = 256;
    let std_dev = 3.2;
    let dimension = 4;
    let mut rng = rand::thread_rng();

    let secret_key = keys::SecretKey::generate(dimension, q, &mut rng);
    let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);

    let msg_1 = vec![0, 1, 2, 3];
    let plaintext_1 = plaintext::Plaintext::new(msg_1, t, q);
    let ciphertext_1 = plaintext_1.encrypt(public_key.clone(), std_dev, &mut rng);
    let decrypted_1 = ciphertext_1.decrypt(secret_key.clone());
    assert_eq!(decrypted_1.poly.val, plaintext_1.poly.val);

    let msg_2 = vec![2, 3, 1, 0];
    let plaintext_2 = plaintext::Plaintext::new(msg_2, t, q);
    let ciphertext_2 = plaintext_2.encrypt(public_key, std_dev, &mut rng);
    let decrypted_2 = ciphertext_2.decrypt(secret_key.clone());
    assert_eq!(decrypted_2.poly.val, plaintext_2.poly.val);

    // Homomorphic addition
    let added_ciphertext = ciphertext_1.clone() + ciphertext_2.clone();
    let decrypted_add = added_ciphertext.decrypt(secret_key.clone());
    assert_eq!(
        decrypted_add.poly.val,
        (plaintext_1.poly.clone() + plaintext_2.poly.clone()).unsigned_modulo(t).val
    );

    // Homomoprhic multiplication setup
    let _rlk_1 = secret_key.relinearization_key_gen_1(std_dev, &mut rng);
    let _rlk_simple = secret_key.relinearization_key_gen_simple(std_dev, &mut rng);
    let p = q.pow(3);
    let std_dev_prime = std_dev * 2.0;
    let rlk_2 = secret_key.relinearization_key_gen_2(std_dev_prime, &mut rng, p);

    // Homomorphic multiplication
    let mul_ciphertext = ciphertext_1.clone().mul_2(ciphertext_2.clone(), rlk_2);
    println!("mul ciphertext: {:?}", mul_ciphertext);
    let decrypted_mul = mul_ciphertext.decrypt(secret_key.clone());
    println!("decrypted mul: {:?}", decrypted_mul.poly);
    assert_eq!(
        decrypted_mul.poly.val,
        (plaintext_1.poly.clone() * plaintext_2.poly.clone()).unsigned_modulo(t).val
    );
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
