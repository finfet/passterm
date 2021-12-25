# Terminal Password Prompt

Easily get a password from the terminal.

This crate provides a cross-platform way to disable terminal echo.

Tested on Linux, macOS, and Windows. BSD will also probably work but hasn't
been tested.

The windows portion uses the new official windows crate instead of
the older winapi crate.

This is similar to python's getpass functionality.

Example

```rust
use passterm::read_password;
std::io::Write;

print!("New password: ");
std::io::stdout().flush()?;
let pass = read_password()?;
println!();

println!("Your password is: {}", pass.as_str());
```

See `examples/pass.rs` for a complete example.
