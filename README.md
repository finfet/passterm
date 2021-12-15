# Terminal Password Prompt

Cross platform way to disable terminal echo. Works on Linux/BSD, macOS, and
Windows.

This is similar to python's getpass functionality.

Example

```rust
use passterm::read_password;

print!("Password: ");
let pass = read_password().unwrap();
```

See `examples/pass.rs` for a complete example.