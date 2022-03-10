# B/FV homomorphic encryption scheme

This is a toy implementation of the [B](https://eprint.iacr.org/2012/078.pdf)/[FV](https://eprint.iacr.org/2012/144.pdf) homomorphic encryption scheme. The existing library is only somewhat homomorphic: encryption, decryption, ciphertext addition and multiplication are supported, but only up to a certain multiplicative depth. For Fully Homomorphic Encryption (FHE), an implementation of bootstrapping is currently under development.

## Example

The following example shows how to:
1. Generate secret, public, and relinearization keys
2. Encrypt plaintexts
3. Add and multiply ciphertexts
4. Decrypt ciphertexts

```rust
extern crate rand;
use rand::SeedableRng;

extern crate bfv;
use bfv::{SecretKey, Plaintext};

// Set the parameters for this instantiation of B/FV
let t = 12;         // Plaintext modulus
let q = 65536;      // Ciphertext modulus
let std_dev = 3.2;  // Standard deviation for generating the error
let degree = 4;     // Degree of polynomials used for encoding and encrypting messages
let rlk_base = (q as f64).log2() as i64; // The base for decomposition during relinearization

// Generate a seeded RNG. Any Rng that imlements RngCore + CryptoRng can be used.
let mut rng = rand::rngs::StdRng::seed_from_u64(18);

// Generate secret, public, and relinearization keys using the given parameters
let secret_key = SecretKey::generate(degree, &mut rng);
let public_key = secret_key.public_key_gen(q, std_dev, &mut rng);
let rlk_1 = secret_key.relin_key_gen_1(q, std_dev, &mut rng, rlk_base);

// Generate random plaintexts
let pt_1 = Plaintext::rand(degree, t, &mut rng);
let pt_2 = Plaintext::rand(degree, t, &mut rng);
let pt_3 = Plaintext::rand(degree, t, &mut rng);

// Encrypt the plaintexts
let ct_1 = pt_1.encrypt(&public_key, std_dev, &mut rng);
let ct_2 = pt_2.encrypt(&public_key, std_dev, &mut rng);
let ct_3 = pt_3.encrypt(&public_key, std_dev, &mut rng);

// Multiply and add the ciphertexts: ct_1 * ct_2 + ct_3
// Note: multiplication requires the relinearization key
let expr_ct = ct_1 * (ct_2, &rlk_1) + ct_3;

// Decrypt the result of the evaluation
let expr_pt = expr_ct.decrypt(&secret_key);

// Compare the expected output to the decrypted output
let expected_pt = (pt_1.poly() * pt_2.poly() + pt_3.poly()) % (t, degree);
assert_eq!(expr_pt.poly(), expected_pt)
```

## Links

- [B'12 paper](https://eprint.iacr.org/2012/078.pdf)
- [FV'12 paper](https://eprint.iacr.org/2012/144.pdf)

## Installation & Use

To use this library, you will need the Rust compiler. The compiler can be
installed on linux and osx with the following command:

```bash
curl  --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Other rust installation methods are available on the
[rust website](https://forge.rust-lang.org/infra/other-installation-methods.html).

Build with `cargo build`, run tests with `cargo test`.

