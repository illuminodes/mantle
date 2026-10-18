use std::sync::LazyLock;

use k256::ProjectivePoint;

use super::odd_multiples::OddMultiples;

pub(super) struct GeneratorTables {
    pub(super) base: OddMultiples<64>,
    pub(super) lambda: OddMultiples<64>,
}

static SHARED: LazyLock<GeneratorTables> = LazyLock::new(GeneratorTables::build);

impl GeneratorTables {
    pub(super) const WINDOW: u32 = 8;

    pub(super) fn shared() -> &'static Self {
        &SHARED
    }

    fn build() -> Self {
        let base = OddMultiples::of(&ProjectivePoint::GENERATOR);
        let lambda = base.endomorphism();
        Self { base, lambda }
    }
}
