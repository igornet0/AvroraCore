//! Production `dmc-pgwire` (D4-A): the legacy engine is retired.
//!
//! pgwire is served by the SQL plane — the same encrypted, authenticated, authorized
//! reference path as DMC IPC — co-hosted by `dmc serve --pgwire 127.0.0.1:15432`
//! (SASL `AVRORA-ED25519-V1`, loopback only). This binary no longer opens any storage or
//! listens on any port: it refuses (fail closed) instead of falling back to the legacy
//! engine, whatever the arguments.

fn main() {
    eprintln!(
        "dmc-pgwire: the legacy pgwire engine is retired (D4-A). Production pgwire runs on \
         the SQL plane: `dmc serve --pgwire 127.0.0.1:15432` (SASL {}, loopback only).",
        dmc_pgwire::MECHANISM
    );
    std::process::exit(2);
}
