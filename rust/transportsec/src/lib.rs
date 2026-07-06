//! Transport security primitives for the e-voting PoC.
//!
//! All transport-layer signatures (Ed25519) and key agreement (X25519 ECDH)
//! are implemented HERE in Rust; the Go side calls these functions through
//! the C ABI and never implements or duplicates this cryptography.
//!
//! ABI conventions:
//! - All byte buffers are caller-allocated, fixed-size.
//! - Return code 0 = success, negative = error.
//! - Ed25519: 32-byte seed (private), 32-byte public key, 64-byte signature.
//! - X25519: 32-byte private scalar, 32-byte public point, 32-byte shared secret.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

const OK: i32 = 0;
const ERR_NULL: i32 = -1;
const ERR_BADKEY: i32 = -2;
const ERR_VERIFY: i32 = -3;

/// Generate an Ed25519 keypair. Writes 32-byte seed and 32-byte public key.
#[no_mangle]
pub extern "C" fn ts_ed25519_keygen(seed_out: *mut u8, pub_out: *mut u8) -> i32 {
    if seed_out.is_null() || pub_out.is_null() {
        return ERR_NULL;
    }
    let signing = SigningKey::generate(&mut OsRng);
    unsafe {
        std::ptr::copy_nonoverlapping(signing.to_bytes().as_ptr(), seed_out, 32);
        std::ptr::copy_nonoverlapping(signing.verifying_key().to_bytes().as_ptr(), pub_out, 32);
    }
    OK
}

/// Sign `msg_len` bytes at `msg` with the 32-byte seed. Writes 64-byte signature.
#[no_mangle]
pub extern "C" fn ts_ed25519_sign(
    seed: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
) -> i32 {
    if seed.is_null() || (msg.is_null() && msg_len > 0) || sig_out.is_null() {
        return ERR_NULL;
    }
    let seed_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(seed, 32) }
        .try_into()
        .unwrap();
    let signing = SigningKey::from_bytes(&seed_bytes);
    let msg_slice = if msg_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(msg, msg_len) }
    };
    let sig = signing.sign(msg_slice);
    unsafe { std::ptr::copy_nonoverlapping(sig.to_bytes().as_ptr(), sig_out, 64) };
    OK
}

/// Verify a 64-byte signature over `msg` against a 32-byte public key.
/// Returns 0 if valid, ERR_VERIFY if invalid, ERR_BADKEY if the key is malformed.
#[no_mangle]
pub extern "C" fn ts_ed25519_verify(
    pubkey: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> i32 {
    if pubkey.is_null() || (msg.is_null() && msg_len > 0) || sig.is_null() {
        return ERR_NULL;
    }
    let pub_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(pubkey, 32) }
        .try_into()
        .unwrap();
    let verifying = match VerifyingKey::from_bytes(&pub_bytes) {
        Ok(k) => k,
        Err(_) => return ERR_BADKEY,
    };
    let sig_bytes: [u8; 64] = unsafe { std::slice::from_raw_parts(sig, 64) }
        .try_into()
        .unwrap();
    let signature = Signature::from_bytes(&sig_bytes);
    let msg_slice = if msg_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(msg, msg_len) }
    };
    match verifying.verify(msg_slice, &signature) {
        Ok(()) => OK,
        Err(_) => ERR_VERIFY,
    }
}

/// Generate an X25519 keypair. Writes 32-byte private scalar and 32-byte public point.
#[no_mangle]
pub extern "C" fn ts_x25519_keygen(priv_out: *mut u8, pub_out: *mut u8) -> i32 {
    if priv_out.is_null() || pub_out.is_null() {
        return ERR_NULL;
    }
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = XPublicKey::from(&secret);
    unsafe {
        std::ptr::copy_nonoverlapping(secret.to_bytes().as_ptr(), priv_out, 32);
        std::ptr::copy_nonoverlapping(public.to_bytes().as_ptr(), pub_out, 32);
    }
    OK
}

/// X25519 Diffie-Hellman: shared = priv * peer_pub. Writes 32-byte shared secret.
/// Returns ERR_BADKEY if the result is the all-zero point (contributory check).
#[no_mangle]
pub extern "C" fn ts_x25519_dh(
    privkey: *const u8,
    peer_pub: *const u8,
    shared_out: *mut u8,
) -> i32 {
    if privkey.is_null() || peer_pub.is_null() || shared_out.is_null() {
        return ERR_NULL;
    }
    let priv_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(privkey, 32) }
        .try_into()
        .unwrap();
    let pub_bytes: [u8; 32] = unsafe { std::slice::from_raw_parts(peer_pub, 32) }
        .try_into()
        .unwrap();
    let secret = StaticSecret::from(priv_bytes);
    let shared = secret.diffie_hellman(&XPublicKey::from(pub_bytes));
    if !shared.was_contributory() {
        return ERR_BADKEY;
    }
    unsafe { std::ptr::copy_nonoverlapping(shared.as_bytes().as_ptr(), shared_out, 32) };
    OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_roundtrip() {
        let mut seed = [0u8; 32];
        let mut pk = [0u8; 32];
        assert_eq!(ts_ed25519_keygen(seed.as_mut_ptr(), pk.as_mut_ptr()), OK);
        let msg = b"ballot box export, CC1 -> CC2";
        let mut sig = [0u8; 64];
        assert_eq!(
            ts_ed25519_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()),
            OK
        );
        assert_eq!(
            ts_ed25519_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
            OK
        );
        // Tampered message must fail.
        let bad = b"ballot box export, CC1 -> CC3";
        assert_eq!(
            ts_ed25519_verify(pk.as_ptr(), bad.as_ptr(), bad.len(), sig.as_ptr()),
            ERR_VERIFY
        );
    }

    #[test]
    fn x25519_agreement() {
        let (mut a_priv, mut a_pub) = ([0u8; 32], [0u8; 32]);
        let (mut b_priv, mut b_pub) = ([0u8; 32], [0u8; 32]);
        assert_eq!(ts_x25519_keygen(a_priv.as_mut_ptr(), a_pub.as_mut_ptr()), OK);
        assert_eq!(ts_x25519_keygen(b_priv.as_mut_ptr(), b_pub.as_mut_ptr()), OK);
        let (mut s1, mut s2) = ([0u8; 32], [0u8; 32]);
        assert_eq!(ts_x25519_dh(a_priv.as_ptr(), b_pub.as_ptr(), s1.as_mut_ptr()), OK);
        assert_eq!(ts_x25519_dh(b_priv.as_ptr(), a_pub.as_ptr(), s2.as_mut_ptr()), OK);
        assert_eq!(s1, s2);
    }
}
