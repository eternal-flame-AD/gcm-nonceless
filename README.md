# gcm-nonceless

Decrypts GCM encrypted data without access to the nonce.

Similar to situations in the following Stack Exchange question (note as of today the accepted answer is incorrect, you do not need any prior knowledge of the plaintext to decrypt the data with a lost nonce):

- ["Can an AES-GCM be cracked if the key is known but the nonce isn't?"](https://crypto.stackexchange.com/questions/79556/can-an-aes-gcm-be-cracked-if-the-key-is-known-but-the-nonce-isnt)

## ⚠️ Security Warning: Hazmat!

This is super sketchy cryptanalysis and should not be used in production but security research, forensics and data salvage applications.

All integrity and authenticity guarantees of AES-GCM are lost.

## Theory of Operation

Firstly, reconstruct the GHASH key $H$.

$$
H = E_{K}(0^{128})
$$

Given the relationship:

$$
T = \mathtt{GHASH}_{H}(A, C) \oplus E_{K}(Y_0)
$$

Rearrange. This part is done in `recover_counter`.

$$
E_{K}(Y_0) = \mathtt{GHASH}_{H}(A, C) \oplus T
$$

$$
Y_0 = E_{K}^{-1}(\mathtt{GHASH}_{H}(A, C) \oplus T)
$$

For practical purposes using standard 12 byte nonces, initialization vector $\mathtt{IV}$ is simply the first 12 bytes of $Y_0$ by construction. This is done in `extract_nonce`.

$$
Y_0 = \mathtt{IV} || 0^{31}1
$$

For other nonce lengths, the initialization vector cannot be deterministically deduced, but the exact original nonce is not required for any further decryption. The following decryption always holds:

$$
P = \mathtt{CTR}_{32}(E_{K}, \mathtt{INCR}_{32}(Y_0), C)
$$

## Usage

Here's a piece of data [encrypted](<https://cyberchef.org/#recipe=AES_Encrypt(%7B'option':'Latin1','string':'YELLOW%20SUBMARINE'%7D,%7B'option':'Hex','string':'6a09e667f3bcc908bb67ae85'%7D,'GCM','Raw','Hex',%7B'option':'Hex','string':'AEADAEAD'%7D)&input=TWVldCBtZSBhdCAzNS44OTI3OCwgMTM3LjQ4MDI4>) using the first 12 bytes of SHA-512 initial hash value as the nonce:

```sh
echo 'ba0c7b18f7a44ade467aaca68ea871f5a7ccee25ee55d8167f062e92555e' \
     'd0cebad09f801a557bc40a5ba6354fec' \
    | xxd -r -p \
    | cargo run --features cli -- -caes-128 \
      -a AEADAEAD \
      --key 'YELLOW SUBMARINE'
Recovered nonce: 6a09e667f3bcc908bb67ae85
Meet me at 35.89278, 137.48028
```

Library usage:

```rust
use gcm_nonceless::{extract_nonce, instantiate_keystream, recover_counter};
use aes::cipher::{StreamCipher, generic_array::GenericArray, KeyInit};
let mut ct = *b"\xba\x0c\x7b\x18\xf7\xa4\x4a\xde\x46\x7a\xac\xa6\x8e\xa8\x71\xf5\xa7\xcc\xee\x25\xee\x55\xd8\x16\x7f\x06\x2e\x92\x55\x5e";
let tag =
    GenericArray::from(*b"\xd0\xce\xba\xd0\x9f\x80\x1a\x55\x7b\xc4\x0a\x5b\xa6\x35\x4f\xec");
let aad = *b"\xAE\xAD\xAE\xAD";
let key = GenericArray::from(*b"YELLOW SUBMARINE");
let cipher = aes::Aes128::new(&key);
let y0 = recover_counter(&cipher, &ct, &Some(tag), &aad);

let recovered_nonce = extract_nonce::<aes::Aes128>(&y0).unwrap();
assert_eq!(
    recovered_nonce.as_slice(),
    b"\x6a\x09\xe6\x67\xf3\xbc\xc9\x08\xbb\x67\xae\x85"
);
let mut recovered_keystream = instantiate_keystream(&cipher, &y0);
recovered_keystream.apply_keystream(&mut ct);
assert_eq!(ct.as_slice(), b"Meet me at 35.89278, 137.48028");
```
