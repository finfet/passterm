# Terminal Utilities

Provides a cross-platform way to disable terminal echo or check if a stream
is a tty.

Functionality similar to python getpass and os.isatty

Tested on Linux, macOS, and Windows. BSD will also probably work but hasn't
been tested.

The windows portion uses the new official windows crate instead of
the older winapi crate.

Example: Get a password

```rust
use passterm::read_password;
std::io::Write;

print!("New password: ");
std::io::stdout().flush()?;
let pass = read_password()?;
println!();

println!("Your password is: {}", pass.as_str());
```

Example: Check if standard output has been redirected

```rust
use passterm::{isatty, Stream}

let is_tty = isatty(Stream::Stdout);
if is_tty {
    println!("We're in a terminal");
} else {
    println!("Not in a terminal. Output was redirected >.");
}
```
