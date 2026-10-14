use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

/// A fixed set of secp256k1 keys the synthetic chain pays to and signs with.
pub struct Keyring {
    keys: Vec<SigningKey>,
    pubkeys: Vec<Vec<u8>>,
    pubkey_hashes: Vec<[u8; 20]>,
}

impl Keyring {
    pub const SIZE: usize = 16;
    const SIGHASH_ALL: u8 = 0x01;

    pub fn new() -> Self {
        let keys: Vec<SigningKey> = (1..=Self::SIZE)
            .map(|i| {
                let secret = [u8::try_from(i).expect("key index fits u8"); 32];
                SigningKey::from_bytes(&secret.into()).expect("nonzero secret")
            })
            .collect();
        let pubkeys: Vec<Vec<u8>> = keys
            .iter()
            .map(|k| k.verifying_key().to_sec1_point(true).as_bytes().to_vec())
            .collect();
        let pubkey_hashes = pubkeys
            .iter()
            .map(|pk| Ripemd160::digest(Sha256::digest(pk)).into())
            .collect();
        Self {
            keys,
            pubkeys,
            pubkey_hashes,
        }
    }

    pub fn pubkey(&self, key: usize) -> &[u8] {
        &self.pubkeys[key]
    }

    pub fn p2pkh_script(&self, key: usize) -> Vec<u8> {
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&self.pubkey_hashes[key]);
        script.extend_from_slice(&[0x88, 0xac]);
        script
    }

    pub fn p2wpkh_script(&self, key: usize) -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&self.pubkey_hashes[key]);
        script
    }

    /// A low-S DER signature over `digest` with the `SIGHASH_ALL` byte appended.
    pub fn sign_all(&self, key: usize, digest: &[u8; 32]) -> Vec<u8> {
        let signature: Signature = self.keys[key].sign_prehash(digest).expect("signing");
        let mut bytes = signature.normalize_s().to_der().as_bytes().to_vec();
        bytes.push(Self::SIGHASH_ALL);
        bytes
    }
}
