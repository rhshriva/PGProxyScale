//! Framing: reading and writing PostgreSQL protocol messages.
//!
//! Design notes
//! ------------
//! * **Buffers are reused per connection.** After warm-up a steady-state relay allocates
//!   nothing, which keeps the data path simple and auditable. Spike S1 showed the
//!   bottleneck is not byte copying, so a zero-copy design would buy nothing here.
//! * **[`Frame::raw`] contains the whole message including tag and length**, so
//!   forwarding a message the proxy does not care about is a single `write_all` with no
//!   re-framing and no allocation.
//! * **Length checks happen before allocation.** An untrusted client — increasingly, an
//!   agent — must not be able to make the proxy allocate on request.

use std::io::{self, Read, Write};

use super::startup::{self, StartupRequest};
use super::{DEFAULT_MAX_MESSAGE_LEN, MIN_MESSAGE_LEN};

/// A borrowed view of one framed message.
///
/// The two slices point into the reader's reusable buffer: `raw` is the complete message,
/// `payload` is just the body. Both are invalidated by the next read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Message type tag.
    pub tag: u8,
    /// Message body, excluding tag and length.
    pub payload: &'a [u8],
    /// The complete message: tag, length, payload.
    pub raw: &'a [u8],
}

impl Frame<'_> {
    /// Length of the message as it appears on the wire.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Whether the message has an empty body.
    pub fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Reads framed messages from a stream, reusing one buffer.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    buf: Vec<u8>,
    max_message_len: usize,
}

impl<R: Read> FrameReader<R> {
    /// Wrap a reader with the default message-size cap.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
        }
    }

    /// Wrap a reader with an explicit message-size cap.
    pub fn with_max_message_len(inner: R, max_message_len: usize) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            max_message_len,
        }
    }

    /// Access the underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Consume the reader, returning the underlying stream.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// The reusable buffer backing the most recent [`Frame`].
    pub fn buffer(&self) -> &[u8] {
        &self.buf
    }

    /// Current buffer capacity, for memory diagnostics.
    pub fn buffer_capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Read the startup message, consuming the startup phase.
    ///
    /// The returned value is owned, so the buffer is free for subsequent frame reads.
    pub fn read_startup(&mut self) -> io::Result<StartupRequest> {
        let mut length_buf = [0u8; 4];
        self.inner.read_exact(&mut length_buf)?;
        let length = i32::from_be_bytes(length_buf);

        if length < MIN_MESSAGE_LEN {
            return Err(invalid_data(format!(
                "startup length {length} is below the minimum of {MIN_MESSAGE_LEN}"
            )));
        }
        let body_len = (length - MIN_MESSAGE_LEN) as usize;
        if body_len > self.max_message_len {
            return Err(invalid_data(format!(
                "startup body of {body_len} bytes exceeds the {}-byte limit",
                self.max_message_len
            )));
        }

        // The body always starts with the protocol version or a request code.
        if body_len < 4 {
            return Err(invalid_data(
                "startup body is too short to contain a protocol version".to_string(),
            ));
        }

        self.buf.clear();
        self.buf.resize(body_len, 0);
        self.inner.read_exact(&mut self.buf)?;

        startup::parse_startup(&self.buf)
    }

    /// Read one typed message.
    ///
    /// Returns `Ok(None)` on a *clean* end of stream at a message boundary, which is how
    /// a client disconnecting normally presents. A stream that ends mid-message is an
    /// error, because silently treating a truncated frame as a clean close would hide
    /// real protocol corruption.
    pub fn read_message(&mut self) -> io::Result<Option<Frame<'_>>> {
        // Read the tag separately so a clean EOF is distinguishable from a truncation.
        let mut tag_buf = [0u8; 1];
        match self.inner.read(&mut tag_buf) {
            Ok(0) => return Ok(None),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return self.read_message(),
            Err(e) => return Err(e),
        }
        let tag = tag_buf[0];

        let mut length_buf = [0u8; 4];
        self.inner.read_exact(&mut length_buf)?;
        let length = i32::from_be_bytes(length_buf);

        if length < MIN_MESSAGE_LEN {
            return Err(invalid_data(format!(
                "message {:?} has length {length}, below the minimum of {MIN_MESSAGE_LEN}",
                super::frontend_name(tag)
            )));
        }
        let payload_len = (length - MIN_MESSAGE_LEN) as usize;
        if payload_len > self.max_message_len {
            return Err(invalid_data(format!(
                "message {:?} body of {payload_len} bytes exceeds the {}-byte limit",
                super::frontend_name(tag),
                self.max_message_len
            )));
        }

        self.buf.clear();
        self.buf.reserve(5 + payload_len);
        self.buf.push(tag);
        self.buf.extend_from_slice(&length_buf);
        self.buf.resize(5 + payload_len, 0);
        self.inner.read_exact(&mut self.buf[5..])?;

        // Both slices borrow the same buffer immutably, which is fine; `raw` is what the
        // relay writes straight through, `payload` is what inspection reads.
        let payload = &self.buf[5..];
        Ok(Some(Frame {
            tag,
            payload,
            raw: &self.buf,
        }))
    }
}

/// Writes framed messages to a stream.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    buf: Vec<u8>,
}

impl<W: Write> FrameWriter<W> {
    /// Wrap a writer.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            buf: Vec::new(),
        }
    }

    /// Access the underlying writer.
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Consume the writer, returning the underlying stream.
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Write a typed message, framing it.
    pub fn write_message(&mut self, tag: u8, payload: &[u8]) -> io::Result<()> {
        let length = i32::try_from(payload.len() + MIN_MESSAGE_LEN as usize)
            .map_err(|_| invalid_data("message too large to frame".to_string()))?;

        self.buf.clear();
        self.buf.reserve(1 + 4 + payload.len());
        self.buf.push(tag);
        self.buf.extend_from_slice(&length.to_be_bytes());
        self.buf.extend_from_slice(payload);

        self.inner.write_all(&self.buf)
    }

    /// Write bytes that are already framed, without re-framing or copying.
    ///
    /// This is the relay path: a message the proxy does not need to inspect goes
    /// straight through.
    pub fn write_raw(&mut self, raw: &[u8]) -> io::Result<()> {
        self.inner.write_all(raw)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader(bytes: &[u8]) -> FrameReader<Cursor<Vec<u8>>> {
        FrameReader::new(Cursor::new(bytes.to_vec()))
    }

    #[test]
    fn sync_is_five_bytes_with_length_four() {
        // Golden vector: `Sync` carries no payload, so its length field is exactly 4.
        // Getting this off by one is the classic framing bug.
        let bytes = [b'S', 0, 0, 0, 4];
        let mut r = reader(&bytes);
        let frame = r.read_message().unwrap().expect("a message");
        assert_eq!(frame.tag, b'S');
        assert!(frame.payload.is_empty());
        assert_eq!(frame.raw, &bytes);
        assert_eq!(frame.len(), 5);
    }

    #[test]
    fn length_field_excludes_the_tag_and_includes_itself() {
        // 'Q' + length 5 + one payload byte: length counts 4 length bytes + 1 payload.
        let mut w = FrameWriter::new(Vec::new());
        w.write_message(b'Q', &[0xAB]).unwrap();
        assert_eq!(w.into_inner(), vec![b'Q', 0, 0, 0, 5, 0xAB]);
    }

    #[test]
    fn round_trips_a_message() {
        let payload = b"SELECT 1\0".to_vec();
        let mut w = FrameWriter::new(Vec::new());
        w.write_message(b'Q', &payload).unwrap();
        let encoded = w.into_inner();

        let mut r = reader(&encoded);
        let frame = r.read_message().unwrap().expect("a message");
        assert_eq!(frame.tag, b'Q');
        assert_eq!(frame.payload, payload.as_slice());
        assert!(
            r.read_message().unwrap().is_none(),
            "stream should be exhausted"
        );
    }

    #[test]
    fn clean_eof_at_a_boundary_is_none() {
        let mut r = reader(&[]);
        assert!(r.read_message().unwrap().is_none());
    }

    #[test]
    fn truncated_tag_is_an_error_not_a_clean_close() {
        // One byte of a length field: the peer died mid-message. Treating this as a
        // clean close would hide protocol corruption.
        let mut r = reader(&[b'Q', 0]);
        let err = r.read_message().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn truncated_payload_is_an_error() {
        // Claims 10 payload bytes, supplies 2.
        let mut r = reader(&[b'Q', 0, 0, 0, 14, 1, 2]);
        let err = r.read_message().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_length_below_minimum() {
        let mut r = reader(&[b'Q', 0, 0, 0, 3]);
        let err = r.read_message().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("below the minimum"), "{err}");
    }

    #[test]
    fn rejects_negative_length() {
        let mut r = reader(&[b'Q', 0xFF, 0xFF, 0xFF, 0xFF]);
        let err = r.read_message().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_oversized_message_before_allocating() {
        // A 2 GiB frame from an untrusted client must be refused, not allocated.
        let mut r = FrameReader::with_max_message_len(
            Cursor::new(vec![b'Q', 0x7F, 0xFF, 0xFF, 0xFF]),
            1024,
        );
        let err = r.read_message().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "{err}");
        assert_eq!(
            r.buffer_capacity(),
            0,
            "must not allocate for a rejected frame"
        );
    }

    #[test]
    fn reuses_one_buffer_across_messages() {
        let mut w = FrameWriter::new(Vec::new());
        w.write_message(b'Q', b"one").unwrap();
        w.write_message(b'Q', b"two").unwrap();
        w.write_message(b'Q', b"three").unwrap();
        let encoded = w.into_inner();

        let mut r = reader(&encoded);
        for expected in [b"one".as_slice(), b"two", b"three"] {
            let frame = r.read_message().unwrap().expect("a message");
            assert_eq!(frame.payload, expected);
        }
        // The largest message is 5 payload bytes; capacity must not grow per message.
        let capacity = r.buffer_capacity();
        assert!(
            capacity < 64,
            "buffer grew to {capacity}, so it is not being reused"
        );
    }

    #[test]
    fn write_raw_forwards_without_reframing() {
        let original = [b'S', 0, 0, 0, 4];
        let mut r = reader(&original);
        let frame = r.read_message().unwrap().expect("a message");
        let raw = frame.raw.to_vec();

        let mut w = FrameWriter::new(Vec::new());
        w.write_raw(&raw).unwrap();
        assert_eq!(w.into_inner(), original.to_vec());
    }

    #[test]
    fn reads_a_standard_startup_packet() {
        // length(4) + version(4) + "user\0postgres\0database\0app\0\0"
        let mut body = Vec::new();
        body.extend_from_slice(&super::super::PROTOCOL_3_0.to_be_bytes());
        for (k, v) in [("user", "postgres"), ("database", "app")] {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
        bytes.extend_from_slice(&body);

        let mut r = reader(&bytes);
        let request = r.read_startup().unwrap();
        match request {
            StartupRequest::Startup(params) => {
                assert_eq!(params.protocol_version, super::super::PROTOCOL_3_0);
                assert_eq!(params.get("user"), Some("postgres"));
                assert_eq!(params.get("database"), Some("app"));
            }
            other => panic!("expected a startup message, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversized_startup_before_allocating() {
        // Claims a 2 GiB body.
        let mut r =
            FrameReader::with_max_message_len(Cursor::new(vec![0x7F, 0xFF, 0xFF, 0xFF]), 4096);
        let err = r.read_startup().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "{err}");
    }
}
