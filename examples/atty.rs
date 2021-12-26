use passterm::{isatty, Stream};

fn main() {
    let stdin_tty = isatty(Stream::Stdin);
    let stdout_tty = isatty(Stream::Stdout);
    let stderr_tty = isatty(Stream::Stderr);

    eprintln!("stderr");
    println!("stdout");

    println!("stdin_tty : {}", stdin_tty);
    println!("stdout_tty: {}", stdout_tty);
    println!("stderr_tty: {}", stderr_tty);
}
