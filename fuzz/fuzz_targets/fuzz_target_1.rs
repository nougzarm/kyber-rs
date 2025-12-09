#![no_main]
use libfuzzer_sys::fuzz_target;
use kyber_rs::Kyber768;
use kyber_rs::traits::KemScheme;

fuzz_target!(|data: &[u8]| {
    if data.len() < 97 {
        return;
    }

    let d: &[u8; 32] = data[0..32].try_into().unwrap();
    let z: &[u8; 32] = data[32..64].try_into().unwrap();
    let m: &[u8; 32] = data[64..96].try_into().unwrap();
    
    let corruption_byte = if data[96] == 0 { 1 } else { data[96] };

    let kem = Kyber768::new();

    let (ek, dk) = kem.key_gen_internal(d, z);
    let (shared_secret_bob, ciphertext) = kem.encaps_internal(&ek, m);

    let shared_secret_alice = kem.decaps_internal(&dk, &ciphertext);
    assert_eq!(shared_secret_bob.0, shared_secret_alice.0);
    
    let mut bad_ciphertext = ciphertext.clone();
    if let Some(byte_to_change) = bad_ciphertext.get_mut(0) {
        *byte_to_change ^= corruption_byte;
    }
    
    let shared_secret_corrupted = kem.decaps_internal(&dk, &bad_ciphertext);
    assert_ne!(
        shared_secret_bob.0, 
        shared_secret_corrupted.0
    );
});