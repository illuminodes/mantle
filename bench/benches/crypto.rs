use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as EcdsaSig, SigningKey, VerifyingKey};
use k256::elliptic_curve::ops::{MulByGeneratorVartime, Reduce};
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use mantle_consensus::script::consensus_crypto::Ecdsa;
use std::hint::black_box;

fn main() {
    divan::main();
}

struct Fixture {
    der: Vec<u8>,
    pubkey: Vec<u8>,
    digest: [u8; 32],
    sig: EcdsaSig,
    vk: VerifyingKey,
    q: ProjectivePoint,
    u1: Scalar,
    u2: Scalar,
}

impl Fixture {
    fn new() -> Self {
        let sk = SigningKey::from_bytes(&[11u8; 32].into()).expect("nonzero secret");
        let digest = [0x5au8; 32];
        let sig: EcdsaSig = sk.sign_prehash(&digest).expect("sign");
        let sig = sig.normalize_s();
        let vk = *sk.verifying_key();
        let q = ProjectivePoint::from(*vk.as_affine());
        let (u1, u2) = Self::scalar_prep(&digest, &sig);
        Self {
            der: sig.to_der().as_bytes().to_vec(),
            pubkey: vk.to_sec1_point(true).as_bytes().to_vec(),
            digest,
            sig,
            vk,
            q,
            u1,
            u2,
        }
    }

    fn scalar_prep(digest: &[u8; 32], sig: &EcdsaSig) -> (Scalar, Scalar) {
        let (r, s) = sig.split_scalars();
        let z = <Scalar as Reduce<FieldBytes>>::reduce(&FieldBytes::from(*digest));
        let s_inv = s.invert_vartime().unwrap();
        (z * s_inv, *r * s_inv)
    }

    fn wnaf_window_tables(bases: &[ProjectivePoint; 4]) -> [[ProjectivePoint; 8]; 4] {
        bases.map(|base| {
            let dbl = base.double();
            let mut cur = base;
            core::array::from_fn(|_| {
                let entry = cur;
                cur += dbl;
                entry
            })
        })
    }

    fn verify_bases(&self) -> [ProjectivePoint; 4] {
        let g = ProjectivePoint::GENERATOR;
        [g, g.endomorphism(), self.q, self.q.endomorphism()]
    }

    fn double_and_add(&self) -> ProjectivePoint {
        ProjectivePoint::mul_by_generator_and_mul_add_vartime(&self.u1, &self.u2, &self.q)
    }
}

#[divan::bench]
fn ecdsa_full(bencher: divan::Bencher) {
    let f = Fixture::new();
    bencher.bench(|| Ecdsa::verify(black_box(&f.der), black_box(&f.pubkey), black_box(&f.digest)));
}

#[divan::bench]
fn pubkey_decompress(bencher: divan::Bencher) {
    let f = Fixture::new();
    bencher.bench(|| VerifyingKey::from_sec1_bytes(black_box(&f.pubkey)).is_ok());
}

#[divan::bench]
fn sig_from_slice(bencher: divan::Bencher) {
    let f = Fixture::new();
    let compact = f.sig.to_bytes();
    bencher.bench(|| EcdsaSig::from_slice(black_box(&compact)).is_ok());
}

#[divan::bench]
fn verify_prehash_only(bencher: divan::Bencher) {
    let f = Fixture::new();
    bencher.bench(|| f.vk.verify_prehash(black_box(&f.digest), black_box(&f.sig)).is_ok());
}

#[divan::bench_group]
mod verify_breakdown {
    use super::{Fixture, black_box};

    #[divan::bench]
    fn scalar_prep(bencher: divan::Bencher) {
        let f = Fixture::new();
        bencher.bench(|| Fixture::scalar_prep(black_box(&f.digest), black_box(&f.sig)));
    }

    #[divan::bench]
    fn double_and_add(bencher: divan::Bencher) {
        let f = Fixture::new();
        bencher.bench(|| black_box(&f).double_and_add());
    }

    #[divan::bench]
    fn window_tables_all_four(bencher: divan::Bencher) {
        let f = Fixture::new();
        bencher.bench(|| Fixture::wnaf_window_tables(black_box(&f.verify_bases())));
    }

    #[divan::bench]
    fn to_affine(bencher: divan::Bencher) {
        let f = Fixture::new();
        let p = f.double_and_add();
        bencher.bench(|| black_box(p).to_affine());
    }
}

#[divan::bench_group]
mod point_ops {
    use super::{AffinePoint, Fixture, black_box};

    #[divan::bench]
    fn double(bencher: divan::Bencher) {
        let p = Fixture::new().double_and_add();
        bencher.bench(|| black_box(p).double());
    }

    #[divan::bench]
    fn add_projective(bencher: divan::Bencher) {
        let f = Fixture::new();
        let p = f.double_and_add();
        bencher.bench(|| black_box(p) + black_box(f.q));
    }

    #[divan::bench]
    fn add_mixed_affine(bencher: divan::Bencher) {
        let f = Fixture::new();
        let p = f.double_and_add();
        let a: AffinePoint = f.q.to_affine();
        bencher.bench(|| black_box(p) + black_box(a));
    }

    #[divan::bench]
    fn endomorphism(bencher: divan::Bencher) {
        let p = Fixture::new().double_and_add();
        bencher.bench(|| black_box(p).endomorphism());
    }
}
