# Terminal Utilities

Provides a way to read passwords from a terminal. Terminal echo is disabled
when reading the password.

Also provides the ability to check if a terminal is a tty or not.

This crate provides functionality similar to the python `getpass` and `os.isatty`
functions.

Tested on Linux, macOS, and Windows.

Functions on windows use the new, official windows crate instead of the older
winapi crate.

Example: Get a password

```rust
use passterm::read_password_stdin;
use std::io::Write;

print!("New password: ");
std::io::stdout().flush()?;
let pass = read_password_stdin()?;
println!();

println!("Your password is: {}", pass.as_str());
```

Example: Check if standard output has been redirected

```rust
use passterm::{isatty, Stream};

let is_tty = isatty(Stream::Stdout);
if is_tty {
    println!("We're in a terminal");
} else {
    println!("Not in a terminal. Output was redirected >.");
}
```
