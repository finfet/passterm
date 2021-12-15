// Copyright 2021 Kyle Schreiber
// SPDX-License-Identifier: Apache-2.0

use passterm::read_password;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprint!("New password: ");
    let pass1 = read_password()?;
    eprintln!();

    println!("got: {}", pass1.as_str());

    eprint!("Confirm password: ");
    let pass2 = read_password()?;
    eprintln!();

    println!("got2: {}", pass2.as_str());

    Ok(())
}
