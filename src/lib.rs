#![doc = include_str!("../README.md")]
#![cfg_attr(not(test), no_std)]
#![warn(missing_docs)]
use aes::cipher::{
    BlockCipher, BlockDecrypt, BlockEncrypt, BlockSizeUser, InnerIvInit, KeyInit,
    consts::{U12, U16},
    generic_array::GenericArray,
};
use ctr::CtrCore;
use ghash::{GHash, universal_hash::UniversalHash};

pub use aes;
pub use ctr;
pub use ghash;

/// Recover initial counter block from the ciphertext, tag, and associated data.
///
/// # ⚠️ Security Warning: Hazmat
///
/// The authenticity and integrity of the ciphertext cannot be verified.
///
/// # Arguments
///
/// * `cipher` - The cipher. For most cases, this is the AES-128 or AES-256 cipher.
/// * `c` - The ciphertext.
/// * `tag` - The tag to use. For most cases, this is the last 16 bytes of the ciphertext. If empty, the last 16 bytes of the ciphertext will be used.
/// * `aad` - The associated data to use. For most cases, this is an empty byte array.
pub fn recover_counter<
    C: BlockCipher
        + BlockEncrypt
        + BlockDecrypt
        + BlockSizeUser<BlockSize = <ghash::GHash as BlockSizeUser>::BlockSize>,
>(
    cipher: &C,
    c: &[u8],
    tag: &Option<GenericArray<u8, <ghash::GHash as BlockSizeUser>::BlockSize>>,
    aad: &[u8],
) -> GenericArray<u8, <ghash::GHash as BlockSizeUser>::BlockSize> {
    let mut c = c;
    let tag = match tag {
        Some(t) => t,
        None => {
            let (cc, tt) = c.split_at(c.len() - 16);
            c = cc;
            aes::Block::from_slice(tt)
        }
    };

    // adapted and repurposed from aes-gcm crate
    let mut ghash_key = ghash::Key::default();
    cipher.encrypt_block(&mut ghash_key);

    let mut ghash = GHash::new(&ghash_key);

    ghash.update_padded(aad);
    ghash.update_padded(c);

    let associated_data_bits = (aad.len() as u64) * 8;
    let buffer_bits = (c.len() as u64) * 8;

    let mut block = ghash::Block::default();
    block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
    block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
    ghash.update(&[block]);

    let mut mask = ghash.finalize();
    for (a, b) in mask.iter_mut().zip(tag.iter()) {
        *a ^= *b;
    }

    cipher.decrypt_block(&mut mask);

    mask
}

/// Instantiate GCM keystream from J_0 for decrypting data.
///
/// # Arguments
///
/// * `cipher` - The cipher. For most cases, this is the AES-128 or AES-256 cipher.
/// * `y0` - The initial counter block.
///
/// # Returns
///
/// A `ctr::Ctr32BE` instance positioned at the start of the ciphertext.
pub fn instantiate_keystream<
    C: BlockCipher
        + BlockEncrypt
        + BlockSizeUser<BlockSize = <ghash::GHash as BlockSizeUser>::BlockSize>,
>(
    cipher: C,
    y0: &GenericArray<u8, <C as BlockSizeUser>::BlockSize>,
) -> ctr::Ctr32BE<C> {
    let mut y0_inc = *y0;
    {
        let mut ctr = u32::from_be_bytes(y0_inc[y0.len() - 4..].try_into().unwrap());
        ctr = ctr.wrapping_add(1);
        y0_inc[y0.len() - 4..].copy_from_slice(&ctr.to_be_bytes());
    }
    let ctr = ctr::Ctr32BE::<C>::from_core(CtrCore::inner_iv_init(cipher, &y0_inc));
    ctr
}

/// Extract the nonce from the initial counter block.
///
/// It is recommended to use this function to check your recovered counter block is valid and not gibberish.
///
/// This only applies to encryptions made with a standard 96-bit nonce.
pub const fn extract_nonce<
    C: BlockSizeUser<BlockSize = <ghash::GHash as BlockSizeUser>::BlockSize>,
>(
    y0: &GenericArray<u8, <C as BlockSizeUser>::BlockSize>,
) -> Option<&GenericArray<u8, U12>> {
    #[expect(unused)]
    const ASSERT_Y0_IS_16_BYTES: GenericArray<u8, U16> =
        unsafe { core::mem::zeroed::<aes::Block>() };
    let y0 = unsafe { core::mem::transmute::<&aes::Block, &[u8; 16]>(y0) };
    if y0[12] == 0 && y0[13] == 0 && y0[14] == 0 && y0[15] == 1 {
        Some(unsafe { core::mem::transmute::<&[u8; 16], &GenericArray<u8, U12>>(y0) })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use aes::cipher::StreamCipher;
    use aes_gcm::aead::AeadMutInPlace;

    use super::*;

    #[inline(always)]
    const fn fnv1a(state: u64, data: u64) -> u64 {
        let state = state ^ data;
        state.wrapping_mul(0x100000001b3u64)
    }

    fn test_recover<
        C: BlockCipher + BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
    >() {
        let mut rng = 0xcbf29ce484222325u64;
        let mut key = aes_gcm::Key::<C>::default();

        for rep in 0..5 {
            rng = fnv1a(rng, rep);
            key.chunks_mut(8).enumerate().for_each(|(i, k)| {
                rng = fnv1a(rng, i as u64);
                let bytes = rng.to_be_bytes();
                k.copy_from_slice(&bytes[..k.len()]);
            });
            let aes_cipher = C::new(&key);
            let mut cipher = aes_gcm::AesGcm::<C, U12>::new(&key);

            let mut nonce = aes_gcm::Nonce::<U12>::default();
            nonce.chunks_mut(4).enumerate().for_each(|(i, n)| {
                rng = fnv1a(rng, i as u64);
                let bytes = rng.to_be_bytes();
                n.copy_from_slice(&bytes[..n.len()]);
            });
            let mut plaintext = [0; 128];
            b"RealPlaintext"
                .into_iter()
                .cycle()
                .zip(plaintext.iter_mut())
                .for_each(|(p, c)| *c = *p);

            for pt_len in 0..plaintext.len() {
                for aad in [b"".as_slice(), b"GenuineAAD".as_slice()] {
                    let mut ciphertext = plaintext;

                    let tag = cipher
                        .encrypt_in_place_detached(&nonce, aad, &mut ciphertext[..pt_len])
                        .unwrap();

                    let recovered_j0 =
                        recover_counter(&aes_cipher, &ciphertext[..pt_len], &Some(tag), aad);
                    let recovered_nonce = extract_nonce::<C>(&recovered_j0).unwrap();
                    assert_eq!(recovered_nonce, &nonce);

                    let mut recovered_keystream = instantiate_keystream(&aes_cipher, &recovered_j0);
                    recovered_keystream.apply_keystream(&mut plaintext[..pt_len]);
                    assert_eq!(plaintext[..pt_len], ciphertext[..pt_len]);
                }
            }
        }
    }

    #[test]
    fn test_recover_j0_aes128() {
        test_recover::<aes::Aes128>();
    }

    #[test]
    fn test_recover_j0_aes256() {
        test_recover::<aes::Aes256>();
    }
}
