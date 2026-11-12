//! Server-sent events: an incremental parser and the typed stream built on it.

use crate::Error;
use futures_util::stream::{self, Stream};
use http_body_util::BodyExt;
use socketguard_core::api_types::ApiEvent;
use std::pin::Pin;

/// A stream of typed events; ends when the daemon closes the connection.
pub type EventStream = Pin<Box<dyn Stream<Item = Result<ApiEvent, Error>> + Send>>;

/// One dispatched event, before it is given a type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SseRaw {
    pub event: String,
    pub data: String,
}

/// Incremental SSE parser (the parts of the event-stream format the daemon uses): lines
/// end in LF, CRLF or CR; lines starting with a colon are comments (keep-alives); an empty
/// line dispatches the event collected so far.
#[derive(Debug, Default)]
pub(crate) struct SseParser {
    buf: Vec<u8>,
    event: Option<String>,
    data: Vec<String>,
    /// The last byte of the previous chunk was CR, so a leading LF belongs to it.
    after_cr: bool,
}

impl SseParser {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Feed bytes; returns the events completed by them.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<SseRaw> {
        let mut out = Vec::new();
        for &b in chunk {
            if self.after_cr {
                self.after_cr = false;
                if b == b'\n' {
                    continue;
                }
            }
            match b {
                b'\r' => {
                    self.after_cr = true;
                    self.line(&mut out);
                }
                b'\n' => self.line(&mut out),
                _ => self.buf.push(b),
            }
        }
        out
    }

    fn line(&mut self, out: &mut Vec<SseRaw>) {
        let line = String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned();
        if line.is_empty() {
            if self.event.is_some() || !self.data.is_empty() {
                out.push(SseRaw {
                    event: self.event.take().unwrap_or_else(|| "message".to_string()),
                    data: std::mem::take(&mut self.data).join("\n"),
                });
            }
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line.as_str(), ""),
        };
        match field {
            "event" => self.event = Some(value.to_string()),
            "data" => self.data.push(value.to_string()),
            _ => {} // id, retry: unused
        }
    }
}

pub(crate) fn stream(body: hyper::body::Incoming) -> EventStream {
    struct State {
        body: hyper::body::Incoming,
        parser: SseParser,
        pending: std::collections::VecDeque<SseRaw>,
    }
    let state = State {
        body,
        parser: SseParser::new(),
        pending: Default::default(),
    };
    Box::pin(stream::unfold(state, |mut st| async move {
        loop {
            if let Some(raw) = st.pending.pop_front() {
                return Some((Ok(ApiEvent::from_wire(&raw.event, &raw.data)), st));
            }
            match st.body.frame().await {
                None => return None,
                Some(Err(e)) => return Some((Err(Error::Protocol(e.to_string())), st)),
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        st.pending.extend(st.parser.feed(data));
                    }
                }
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(event: &str, data: &str) -> SseRaw {
        SseRaw {
            event: event.into(),
            data: data.into(),
        }
    }

    #[test]
    fn parses_events_with_and_without_data() {
        let mut p = SseParser::new();
        let got = p.feed(b"event: apps_changed\ndata:\n\nevent: app_discovered\ndata: abc123\n\n");
        assert_eq!(
            got,
            vec![raw("apps_changed", ""), raw("app_discovered", "abc123")]
        );
    }

    #[test]
    fn handles_chunks_split_anywhere_and_crlf() {
        let wire =
            b"event: peers_changed\r\ndata:\r\n\r\n: keep-alive\n\nevent: activity\ndata:\n\n";
        for split in 0..wire.len() {
            let mut p = SseParser::new();
            let mut got = p.feed(&wire[..split]);
            got.extend(p.feed(&wire[split..]));
            assert_eq!(
                got,
                vec![raw("peers_changed", ""), raw("activity", "")],
                "split at {split}"
            );
        }
    }

    #[test]
    fn comments_alone_dispatch_nothing_and_multiline_data_joins() {
        let mut p = SseParser::new();
        assert!(p.feed(b": hi\n\n").is_empty());
        assert_eq!(
            p.feed(b"data: a\ndata: b\n\n"),
            vec![raw("message", "a\nb")]
        );
    }

    #[test]
    fn events_are_typed() {
        assert_eq!(ApiEvent::from_wire("activity", ""), ApiEvent::Activity);
        assert_eq!(
            ApiEvent::from_wire("app_discovered", "x"),
            ApiEvent::AppDiscovered("x".into())
        );
        assert!(matches!(
            ApiEvent::from_wire("from_the_future", "d"),
            ApiEvent::Unknown { .. }
        ));
    }
}
