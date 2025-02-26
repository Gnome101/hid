use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use silent_threshold_encryption::{
    kzg::PowersOfTau,
    setup::{PublicKey, SecretKey},
};

#[derive(Clone)]
pub enum Curve {
    BLS12_381,
    BN254,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SilentThresholdEncryptionKeypair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn setup<E: Pairing>(
    n: u32,
    party_id: u32,
    params: &PowersOfTau<E>,
) -> Result<SilentThresholdEncryptionKeypair, String> {
    let mut rng = thread_rng();
    let sk: SecretKey<E> = SecretKey::<E>::new(&mut rng);
    let pk: PublicKey<E> = sk.get_pk(party_id as usize, params, n as usize);

    let secret_key = to_bytes(sk);
    let public_key = to_bytes(pk);

    Ok(SilentThresholdEncryptionKeypair {
        secret_key,
        public_key,
    })
}

/// Serialize this to a vector of bytes.
pub fn to_bytes<T: CanonicalSerialize>(elt: T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(elt.compressed_size());
    <T as CanonicalSerialize>::serialize_compressed(&elt, &mut bytes).unwrap();
    bytes
}

/// Deserialize this from a slice of bytes.
pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> T {
    <T as CanonicalDeserialize>::deserialize_compressed(&mut &bytes[..]).unwrap()
}