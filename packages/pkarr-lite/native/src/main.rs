#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    pkarr_lite_native::run()
}
