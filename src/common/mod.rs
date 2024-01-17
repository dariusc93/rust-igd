pub mod messages;
pub mod options;
pub mod parsing;

pub use self::options::SearchOptions;

use const_random::const_random;
use once_cell::sync::Lazy;
use rand::rngs::SmallRng;
use rand::{self, Rng, SeedableRng};

pub static mut RNG: Lazy<SmallRng> = Lazy::new(|| SmallRng::seed_from_u64(const_random!(u64)));

pub fn random_port() -> u16 {
    unsafe { RNG.gen_range(32_768_u16..65_535_u16) }
}
