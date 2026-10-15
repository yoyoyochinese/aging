use console::style;

// Everything here goes to stderr so stdout carries only the result.

pub fn success(msg: &str) {
    let prefix = style("✓").green().bold().for_stderr();
    eprintln!("{prefix} {msg}");
}

pub fn warn(msg: &str) {
    let prefix = style("!").yellow().bold().for_stderr();
    eprintln!("{prefix} {msg}");
}

pub fn error(msg: &str) {
    let prefix = style("✗").red().for_stderr();
    eprintln!("{prefix} {msg}");
}
