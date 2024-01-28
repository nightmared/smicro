use rand::{rngs::ThreadRng, thread_rng};

pub struct State {
    pub rng: ThreadRng,
}

impl State {
    pub fn new() -> Self {
        Self { rng: thread_rng() }
    }
}
