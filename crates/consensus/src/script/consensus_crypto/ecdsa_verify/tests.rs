use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::ops::Reduce;
use k256::{FieldBytes, ProjectivePoint, Scalar};
use sha2::{Digest, Sha256};

use super::EcdsaVerifier;

struct Case {
    q: ProjectivePoint,
    digest: [u8; 32],
    sig: Signature,
}

impl Case {
    fn hashed(tag: &str, i: u32) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(tag.as_bytes());
        h.update(i.to_le_bytes());
        h.finalize().into()
    }

    fn scalar(tag: &str, i: u32) -> Scalar {
        <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(Self::hashed(tag, i)))
    }

    fn signed(i: u32) -> Self {
        let sk = SigningKey::from_bytes(&FieldBytes::from(Self::hashed("key", i))).expect("valid key");
        let digest = Self::hashed("msg", i);
        let sig: Signature = sk.sign_prehash(&digest).expect("sign");
        Self {
            q: ProjectivePoint::from(*sk.verifying_key().as_affine()),
            digest,
            sig,
        }
    }

    fn ours(&self, digest: &[u8; 32], sig: &Signature) -> bool {
        let (r, s) = sig.split_scalars();
        EcdsaVerifier::verify(&self.q, digest, &r, &s)
    }

    fn k256(&self, digest: &[u8; 32], sig: &Signature) -> bool {
        let vk = k256::ecdsa::VerifyingKey::from_affine(self.q.to_affine()).expect("valid key");
        vk.verify_prehash(digest, &sig.normalize_s()).is_ok()
    }
}

#[test]
fn double_scalar_mul_matches_naive_sum() {
    for i in 0..300 {
        let u1 = Case::scalar("u1", i);
        let u2 = Case::scalar("u2", i);
        let q = ProjectivePoint::GENERATOR * Case::scalar("q", i);
        let expected = ProjectivePoint::GENERATOR * u1 + q * u2;
        assert_eq!(EcdsaVerifier::double_scalar_mul(&u1, &u2, &q), expected, "case {i}");
    }
}

#[test]
fn double_scalar_mul_handles_edge_scalars() {
    let q = ProjectivePoint::GENERATOR * Case::scalar("q", 0);
    let edges = [Scalar::ZERO, Scalar::ONE, -Scalar::ONE, Scalar::from(2u64), -Scalar::from(2u64)];
    for u1 in edges {
        for u2 in edges {
            let expected = ProjectivePoint::GENERATOR * u1 + q * u2;
            assert_eq!(EcdsaVerifier::double_scalar_mul(&u1, &u2, &q), expected);
        }
    }
}

#[test]
fn accepts_what_k256_accepts() {
    for i in 0..300 {
        let case = Case::signed(i);
        assert!(case.k256(&case.digest, &case.sig));
        assert!(case.ours(&case.digest, &case.sig), "case {i}");
    }
}

#[test]
fn accepts_high_s_form_like_normalised_k256() {
    for i in 0..50 {
        let case = Case::signed(i);
        let (r, s) = case.sig.split_scalars();
        let high = Signature::from_scalars(*r, -*s).expect("nonzero");
        assert!(case.ours(&case.digest, &high), "case {i}");
    }
}

#[test]
fn rejects_what_k256_rejects() {
    for i in 0..100 {
        let case = Case::signed(i);
        let (r, s) = case.sig.split_scalars();
        let mut wrong_digest = case.digest;
        wrong_digest[i as usize % 32] ^= 1;
        let tweaked_r = Signature::from_scalars(*r + Scalar::ONE, *s).expect("nonzero");
        let tweaked_s = Signature::from_scalars(*r, *s + Scalar::ONE).expect("nonzero");
        for (digest, sig) in [
            (&wrong_digest, &case.sig),
            (&case.digest, &tweaked_r),
            (&case.digest, &tweaked_s),
        ] {
            assert!(!case.k256(digest, sig));
            assert!(!case.ours(digest, sig), "case {i}");
        }
    }
}

#[test]
fn rejects_zero_scalars() {
    let case = Case::signed(0);
    let (r, s) = case.sig.split_scalars();
    assert!(!EcdsaVerifier::verify(&case.q, &case.digest, &Scalar::ZERO, &s));
    assert!(!EcdsaVerifier::verify(&case.q, &case.digest, &r, &Scalar::ZERO));
}
