// Copyright 2021-2023 Kyle Schreiber
// SPDX-License-Identifier: BSD-3-Clause

use passterm::{prompt_password_stdin, prompt_password_tty, Stream};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prompt_stdin()?;
    prompt_tty()?;

    Ok(())
}

fn prompt_stdin() -> Result<(), Box<dyn std::error::Error>> {
    let pass = prompt_password_stdin(Some("Stdin Password: "), Stream::Stdout)?;
    println!("You entered: {}", &pass);

    Ok(())
}

fn prompt_tty() -> Result<(), Box<dyn std::error::Error>> {
    let pass = prompt_password_tty(Some("Tty password: "))?;
    println!("You entered: {}", &pass);

    Ok(())
}
