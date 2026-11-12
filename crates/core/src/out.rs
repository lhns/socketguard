//! Standard output that survives a reader which stops reading (`socketguard ... | head -1`,
//! `grep -q`): `println!` panics when the pipe is closed (exit status 101 and a panic message).
//! A closed pipe ends the program quietly with status 0 instead, on every platform. Rust
//! ignores SIGPIPE, so on Unix the write fails with `BrokenPipe` rather than killing the
//! process, which also keeps a vanished daemon (a socket write) an error and not a signal.

use std::io::Write;

/// Write `args` to `w`. A closed pipe calls `on_closed` (the program's exit); any other
/// error is returned.
pub fn write_to(
    w: &mut impl Write,
    args: std::fmt::Arguments<'_>,
    on_closed: impl FnOnce(),
) -> std::io::Result<()> {
    match w.write_fmt(args).and_then(|()| w.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            on_closed();
            Ok(())
        }
        other => other,
    }
}

/// What `out!` and `outln!` call.
#[doc(hidden)]
pub fn stdout(args: std::fmt::Arguments<'_>) {
    let mut out = std::io::stdout().lock();
    if let Err(e) = write_to(&mut out, args, || std::process::exit(0)) {
        eprintln!("error: cannot write to the standard output: {e}");
        std::process::exit(1);
    }
}

/// `print!` that ends the program quietly when the reader has gone.
#[macro_export]
macro_rules! out {
    ($($arg:tt)*) => { $crate::out::stdout(format_args!($($arg)*)) };
}

/// `println!` that ends the program quietly when the reader has gone.
#[macro_export]
macro_rules! outln {
    () => { $crate::out::stdout(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::out::stdout(format_args!("{}\n", format_args!($($arg)*))) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};

    struct Failing(ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.0))
        }
    }

    #[test]
    fn a_closed_pipe_calls_on_closed_and_is_not_an_error() {
        let mut called = false;
        let r = write_to(
            &mut Failing(ErrorKind::BrokenPipe),
            format_args!("x"),
            || called = true,
        );
        assert!(r.is_ok());
        assert!(called);
    }

    #[test]
    fn other_errors_are_returned() {
        let mut called = false;
        let r = write_to(
            &mut Failing(ErrorKind::StorageFull),
            format_args!("x"),
            || called = true,
        );
        assert!(r.is_err());
        assert!(!called);
    }

    #[test]
    fn a_working_writer_gets_the_text() {
        let mut buf = Vec::new();
        write_to(&mut buf, format_args!("a{}\n", 1), || panic!("closed")).unwrap();
        assert_eq!(buf, b"a1\n");
    }
}
