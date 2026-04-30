#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    enlace::fuzzing::http_relay_client_response(data);
});
