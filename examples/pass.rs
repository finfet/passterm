// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

use passterm::read_password_stdin;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print!("New password: ");
    std::io::stdout().flush()?;
    let pass1 = read_password_stdin()?;
    println!();

    println!("got: {}", pass1.as_str());

    print!("Confirm password: ");
    std::io::stdout().flush()?;
    let pass2 = read_password_stdin()?;
    println!();

    println!("got2: {}", pass2.as_str());

    Ok(())
}
