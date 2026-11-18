//! Writing to stdout. Decrypted output is built in zeroized buffers.

use std::io::{self, IsTerminal as _, Write as _};

use openwarden::{ExposeSecret as _, SecretString};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::Common;
use crate::error::{CliError, Result};

/// Prints `value` as JSON (indented with `--pretty`).
pub fn json(value: &impl Serialize, common: &Common) -> Result<()> {
    let mut buf = Zeroizing::new(Vec::with_capacity(4096));
    let written = if common.pretty {
        serde_json::to_writer_pretty(&mut *buf, value)
    } else {
        serde_json::to_writer(&mut *buf, value)
    };
    written.map_err(|err| CliError::json("the output", &err))?;
    buf.push(b'\n');
    write(&buf)
}

/// Prints a value (a password, a session key): a newline only at a
/// terminal, so `$(ow get password x)` and pipes get the value exactly.
pub fn value(secret: &SecretString) -> Result<()> {
    let mut buf = Zeroizing::new(secret.expose_secret().as_bytes().to_vec());
    if io::stdout().is_terminal() {
        buf.push(b'\n');
    }
    write(&buf)
}

/// Prints a message, unless `--quiet`.
pub fn message(text: &str, common: &Common) -> Result<()> {
    if common.quiet {
        return Ok(());
    }
    write(text.as_bytes())?;
    write(b"\n")
}

fn write(bytes: &[u8]) -> Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(bytes)
        .and_then(|()| out.flush())
        .map_err(CliError::Output)
}

/// A note on stderr, unless `--quiet`.
pub fn note(text: &str, common: &Common) {
    if !common.quiet {
        let _ = writeln!(io::stderr(), "ow: {text}");
    }
}
