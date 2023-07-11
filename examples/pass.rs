// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

use passterm::{prompt_password_tty, read_password_stdin};
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prompt_stdin()?;
    prompt_tty()?;

    Ok(())
}

fn prompt_stdin() -> Result<(), Box<dyn std::error::Error>> {
    print!("stdin password: ");
    std::io::stdout().flush()?;
    let pass = read_password_stdin()?;
    println!();
    println!("You entered: {}", &pass);

    Ok(())
}

fn prompt_tty() -> Result<(), Box<dyn std::error::Error>> {
    let pass = prompt_password_tty("Tty password: ")?;
    println!("You entered: {}", &pass);

    Ok(())
}
