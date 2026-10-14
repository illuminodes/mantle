/// How much connected but uncommitted work the pipeline may hold.
///
/// More blocks in flight keep the script workers fed across blocks with few
/// inputs and across slow commits; the input cap bounds the memory the held
/// blocks and their coin maps take.
#[derive(Clone, Copy, Debug)]
pub struct InFlightLimit {
    pub blocks: usize,
    pub inputs: usize,
}

impl InFlightLimit {
    #[must_use]
    pub fn is_exceeded_by(&self, blocks: usize, inputs: usize) -> bool {
        blocks > self.blocks || inputs > self.inputs
    }
}

impl Default for InFlightLimit {
    fn default() -> Self {
        Self {
            blocks: 64,
            inputs: 400_000,
        }
    }
}
