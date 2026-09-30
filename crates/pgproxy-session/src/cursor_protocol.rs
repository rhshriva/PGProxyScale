//! Extended protocol for client-owned held cursors. This never forwards a virtual
//! cursor name to a backend. Portal buffers share immutable snapshot rows and
//! convert only delivered chunks, preserving native utility-cursor positioning.
//!
//! ## Closed-cursor invariant (native suspended-CLOSE dependency)
//!
//! A `CLOSE` of a virtualised cursor is always answered locally, even while an
//! extended portal over that cursor is suspended. The portal keeps its own cached
//! descriptor and immutable row references, so it continues to deliver and complete
//! after the cursor is gone. This is load-bearing: the tested PostgreSQL builds
//! crash in the native equivalent (issuing `CLOSE` on a cursor while a suspended
//! extended portal still references it), so the proxy must never forward that
//! sequence. See `docs/testing/ledger-semantics.md`.
use super::{cursor::CursorMessages, *};
#[derive(Default)]
pub(crate) struct CursorProtocol {
    statements: BTreeMap<String, String>,
    portals: BTreeMap<String, Portal>,
    active: bool,
    failed: bool,
}
struct Portal {
    sql: String,
    formats: Vec<i16>,
    command: Option<Vec<u8>>,
    rows: VecDeque<std::sync::Arc<[u8]>>,
    description: Option<Vec<u8>>,
    fetch: bool,
}
impl CursorProtocol {
    pub(crate) fn bytes(&self) -> usize {
        self.statements
            .iter()
            .map(|(n, s)| n.len() + s.len() + 256)
            .sum::<usize>()
            + self
                .portals
                .iter()
                .map(|(n, p)| {
                    n.len()
                        + p.sql.len()
                        + p.formats.len() * 2
                        + p.rows.capacity() * std::mem::size_of::<std::sync::Arc<[u8]>>()
                        + p.rows.iter().map(|r| r.len() + 16).sum::<usize>()
                        + p.description.as_ref().map_or(0, Vec::capacity)
                        + 256
                })
                .sum::<usize>()
    }
    fn handle(
        &mut self,
        l: &mut SessionLedger,
        tag: u8,
        payload: &[u8],
        idle: bool,
    ) -> Result<Option<CursorMessages>, LedgerError> {
        if self.failed {
            if tag == b'S' {
                self.failed = false;
                self.active = false;
                self.portals.clear();
                return Ok(Some(vec![(b'Z', vec![b'I'])]));
            }
            return Ok(Some(vec![]));
        }
        if tag == b'P' {
            let (name, rest) = cstring(payload)?;
            let (sql, rest) = cstring(rest)?;
            let description = l.cursor_description(&sql)?;
            if description.is_none() {
                if !name.is_empty() && self.statements.contains_key(&name) {
                    return Err(LedgerError::Protocol(
                        "prepared virtual cursor statement already exists",
                    ));
                }
                if name.is_empty() {
                    self.statements.remove("");
                }
                if self.active {
                    return Err(LedgerError::Protocol(
                        "mixed virtual and backend extended cycles require Sync",
                    ));
                }
                return Ok(None);
            }
            if !idle || !l.pending.is_empty() {
                return Err(LedgerError::Protocol(
                    "virtual cursor access requires idle transaction boundary",
                ));
            }
            if rest != [0, 0] {
                return Err(LedgerError::Protocol(
                    "virtual cursor statements take no parameters",
                ));
            }
            if !name.is_empty()
                && (self.statements.contains_key(&name)
                    || l.prepared.contains_key(&name)
                    || l.sql_prepared.contains_key(&name))
            {
                return Err(LedgerError::Protocol("prepared statement already exists"));
            }
            if name.is_empty() {
                l.prepared.remove("");
                self.portals.remove("");
            }
            self.statements.insert(name, sql);
            self.active = true;
            return Ok(Some(vec![(b'1', vec![])]));
        }
        if tag == b'Q' {
            if self.active {
                return Err(LedgerError::Protocol(
                    "virtual extended cycle requires Sync before a simple query",
                ));
            }
            self.statements.remove("");
            self.portals.remove("");
            // SQL PREPARE/DEALLOCATE share the protocol statement namespace. Until
            // their routing is virtualised, don't let the physical namespace diverge.
            if !self.statements.is_empty() {
                let (sql, _) = cstring(payload)?;
                let parsed = l.cache.parse(&sql, l.state.parser_options)?;
                if parsed.tree()["stmts"].as_array().is_some_and(|stmts| {
                    stmts.iter().any(|s| {
                        s["stmt"].get("DeallocateStmt").is_some()
                            || s["stmt"].get("PrepareStmt").is_some()
                    })
                }) {
                    return Err(LedgerError::Protocol(
                        "SQL PREPARE/DEALLOCATE with virtual cursor statements is unsupported",
                    ));
                }
            }
            return Ok(None);
        }
        if tag == b'S' || tag == b'H' {
            if !self.active {
                return Ok(None);
            }
            if !payload.is_empty() {
                return Err(LedgerError::Protocol("invalid Sync/Flush payload"));
            }
            if tag == b'H' {
                return Ok(Some(vec![]));
            }
            self.active = false;
            self.portals.clear();
            return Ok(Some(vec![(b'Z', vec![b'I'])]));
        }
        if tag == b'B' {
            let (portal, rest) = cstring(payload)?;
            let (statement, mut rest) = cstring(rest)?;
            let Some(sql) = self.statements.get(&statement).cloned() else {
                return self.unhandled();
            };
            if !idle {
                return Err(LedgerError::Protocol(
                    "virtual cursor Bind requires idle boundary",
                ));
            }
            let parameter_formats = count(&mut rest)?;
            for _ in 0..parameter_formats {
                let code = number(&mut rest)?;
                if !(0..=1).contains(&code) {
                    return Err(LedgerError::Protocol("unsupported parameter format"));
                }
            }
            if count(&mut rest)? != 0 {
                return Err(LedgerError::Protocol(
                    "virtual cursor parameters are unsupported",
                ));
            }
            let n = count(&mut rest)?;
            let mut formats = Vec::with_capacity(n);
            for _ in 0..n {
                let code = number(&mut rest)?;
                if !(0..=1).contains(&code) {
                    return Err(LedgerError::Protocol("unsupported result format"));
                }
                formats.push(code);
            }
            if !rest.is_empty() {
                return Err(LedgerError::Protocol("trailing Bind bytes"));
            }
            let description = l
                .cursor_description(&sql)?
                .ok_or(LedgerError::Protocol("virtual cursor no longer exists"))?;
            if let Some(d) = &description {
                format_description(d, &formats)?;
            }
            if !portal.is_empty() && self.portals.contains_key(&portal) {
                return Err(LedgerError::Protocol("portal already exists"));
            }
            self.portals.insert(
                portal,
                Portal {
                    sql,
                    formats,
                    command: None,
                    rows: VecDeque::new(),
                    description: description.clone(),
                    fetch: false,
                },
            );
            self.active = true;
            return Ok(Some(vec![(b'2', vec![])]));
        }
        if tag == b'D' || tag == b'C' {
            let (&kind, rest) = payload
                .split_first()
                .ok_or(LedgerError::Protocol("missing Describe/Close kind"))?;
            let (name, rest) = cstring(rest)?;
            if !rest.is_empty() {
                return Err(LedgerError::Protocol("trailing Describe/Close bytes"));
            }
            let (sql, formats, cached_description) = match kind {
                b'S' => match self.statements.get(&name) {
                    Some(sql) => (sql.clone(), vec![], None),
                    None => return self.unhandled(),
                },
                b'P' => match self.portals.get(&name) {
                    Some(p) => (
                        p.sql.clone(),
                        p.formats.clone(),
                        Some(p.description.clone()),
                    ),
                    None => return self.unhandled(),
                },
                _ => return Err(LedgerError::Protocol("invalid Describe/Close kind")),
            };
            if !idle {
                return Err(LedgerError::Protocol(
                    "virtual cursor Describe/Close requires idle boundary",
                ));
            }
            self.active = true;
            if tag == b'C' {
                if kind == b'S' {
                    self.statements.remove(&name);
                } else {
                    self.portals.remove(&name);
                }
                return Ok(Some(vec![(b'3', vec![])]));
            }
            let description = match cached_description {
                Some(description) => description,
                None => l
                    .cursor_description(&sql)?
                    .ok_or(LedgerError::Protocol("virtual cursor no longer exists"))?,
            };
            let mut replies = Vec::new();
            if kind == b'S' {
                replies.push((b't', vec![0, 0]));
            }
            replies.push(match description {
                Some(d) => (b'T', format_description(&d, &formats)?),
                None => (b'n', vec![]),
            });
            return Ok(Some(replies));
        }
        if tag == b'E' {
            let (portal, rest) = cstring(payload)?;
            let protocol_charge = self.bytes();
            let Some(p) = self.portals.get_mut(&portal) else {
                return self.unhandled();
            };
            if rest.len() != 4 {
                return Err(LedgerError::Protocol("invalid Execute limit"));
            }
            let max_rows = i32::from_be_bytes(rest.try_into().unwrap());
            if max_rows < 0 {
                return Err(LedgerError::Protocol("negative Execute row limit"));
            }
            if !idle {
                return Err(LedgerError::Protocol(
                    "virtual cursor Execute requires idle boundary",
                ));
            }
            self.active = true;
            if p.command.is_some() && !p.fetch {
                self.failed = true;
                return Ok(Some(vec![(
                    b'E',
                    error_response("55000", &format!("portal \"{portal}\" cannot be run")),
                )]));
            }
            if p.command.is_none() {
                let mut query = p.sql.as_bytes().to_vec();
                query.push(0);
                let (reply, previous) = l.cursor_reply(&p.sql)?;
                p.fetch = reply.description.is_some();
                p.description = reply.description;
                p.rows = reply.rows;
                p.command = Some(reply.command);
                l.cursor_external_charge = protocol_charge
                    + p.rows.capacity() * std::mem::size_of::<std::sync::Arc<[u8]>>()
                    + p.rows.iter().map(|r| r.len() + 16).sum::<usize>()
                    + p.description.as_ref().map_or(0, Vec::capacity);
                if let Err(error) = l.check_budget() {
                    if let Some((name, position)) = previous
                        && let Some(cursor) = l.virtual_cursors.get_mut(&name)
                    {
                        cursor.set_position(position);
                    }
                    p.rows = VecDeque::new();
                    p.description = None;
                    p.command = None;
                    l.cursor_external_charge = protocol_charge;
                    return Err(error);
                }
                l.frontend(b'Q', &query)?;
                l.backend(b'C', p.command.as_ref().unwrap())?;
                l.backend(b'Z', b"I")?;
            }
            let count = if max_rows == 0 {
                p.rows.len()
            } else {
                p.rows.len().min(max_rows as usize)
            };
            let mut output = Vec::with_capacity(count + 1);
            for _ in 0..count {
                let row = p.rows.pop_front().unwrap();
                let description = p
                    .description
                    .as_ref()
                    .ok_or(LedgerError::Protocol("missing cursor description"))?;
                output.push((b'D', format_row(&row, description, &p.formats)?));
            }
            if p.fetch && max_rows > 0 && count == max_rows as usize {
                output.push((b's', vec![]));
            } else {
                output.push((
                    b'C',
                    if p.fetch {
                        format!("FETCH {count}\0").into_bytes()
                    } else {
                        p.command
                            .clone()
                            .ok_or(LedgerError::Protocol("missing cursor command completion"))?
                    },
                ));
            }
            return Ok(Some(output));
        }
        self.unhandled()
    }
    fn unhandled(&self) -> Result<Option<CursorMessages>, LedgerError> {
        if self.active {
            Err(LedgerError::Protocol(
                "mixed virtual and backend extended cycles require Sync",
            ))
        } else {
            Ok(None)
        }
    }
}
fn error_response(code: &str, message: &str) -> Vec<u8> {
    let mut payload = b"SERROR\0VERROR\0C".to_vec();
    payload.extend(code.as_bytes());
    payload.extend(b"\0M");
    payload.extend(message.as_bytes());
    payload.extend([0, 0]);
    payload
}
fn number(rest: &mut &[u8]) -> Result<i16, LedgerError> {
    let bytes = rest
        .get(..2)
        .ok_or(LedgerError::Protocol("truncated format list"))?;
    let n = i16::from_be_bytes(bytes.try_into().unwrap());
    *rest = &rest[2..];
    Ok(n)
}
fn count(rest: &mut &[u8]) -> Result<usize, LedgerError> {
    let n = number(rest)?;
    usize::try_from(n).map_err(|_| LedgerError::Protocol("negative format count"))
}
fn fields(description: &[u8]) -> Result<Vec<(usize, u32)>, LedgerError> {
    let mut rest = description;
    let n = count(&mut rest)?;
    let mut result = Vec::with_capacity(n);
    for _ in 0..n {
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or(LedgerError::Protocol("unterminated column name"))?;
        rest = &rest[end + 1..];
        let field = rest
            .get(..18)
            .ok_or(LedgerError::Protocol("truncated column metadata"))?;
        result.push((
            description.len() - rest.len() + 16,
            u32::from_be_bytes(field[6..10].try_into().unwrap()),
        ));
        rest = &rest[18..];
    }
    if !rest.is_empty() {
        return Err(LedgerError::Protocol("trailing column metadata"));
    }
    Ok(result)
}
fn codes(formats: &[i16], n: usize) -> Result<Vec<i16>, LedgerError> {
    match formats.len() {
        0 => Ok(vec![0; n]),
        1 => Ok(vec![formats[0]; n]),
        len if len == n => Ok(formats.to_vec()),
        _ => Err(LedgerError::Protocol(
            "result format count does not match columns",
        )),
    }
}
fn format_description(description: &[u8], formats: &[i16]) -> Result<Vec<u8>, LedgerError> {
    let fields = fields(description)?;
    let codes = codes(formats, fields.len())?;
    let mut output = description.to_vec();
    for ((offset, _), code) in fields.into_iter().zip(codes) {
        output[offset..offset + 2].copy_from_slice(&code.to_be_bytes());
    }
    Ok(output)
}
fn format_row(row: &[u8], description: &[u8], formats: &[i16]) -> Result<Vec<u8>, LedgerError> {
    let fields = fields(description)?;
    let codes = codes(formats, fields.len())?;
    let mut rest = row;
    let n = count(&mut rest)?;
    if n != fields.len() {
        return Err(LedgerError::Protocol("row column count mismatch"));
    }
    let mut output = (n as u16).to_be_bytes().to_vec();
    for ((_, oid), format) in fields.into_iter().zip(codes) {
        let bytes = rest
            .get(..4)
            .ok_or(LedgerError::Protocol("truncated row length"))?;
        let len = i32::from_be_bytes(bytes.try_into().unwrap());
        rest = &rest[4..];
        if len == -1 {
            output.extend((-1i32).to_be_bytes());
            continue;
        }
        let len = usize::try_from(len).map_err(|_| LedgerError::Protocol("invalid row length"))?;
        let value = rest
            .get(..len)
            .ok_or(LedgerError::Protocol("truncated row value"))?;
        rest = &rest[len..];
        let value = if format == 1 {
            binary(oid, value)?
        } else {
            value.to_vec()
        };
        output.extend((value.len() as i32).to_be_bytes());
        output.extend(value);
    }
    if !rest.is_empty() {
        return Err(LedgerError::Protocol("trailing row bytes"));
    }
    Ok(output)
}
fn binary(oid: u32, value: &[u8]) -> Result<Vec<u8>, LedgerError> {
    let text = std::str::from_utf8(value)
        .map_err(|_| LedgerError::Protocol("invalid UTF8 cursor value"))?;
    let bad = || LedgerError::Protocol("invalid binary cursor value");
    match oid {
        16 => match value {
            b"t" => Ok(vec![1]),
            b"f" => Ok(vec![0]),
            _ => Err(bad()),
        },
        20 => Ok(text
            .parse::<i64>()
            .map_err(|_| bad())?
            .to_be_bytes()
            .to_vec()),
        21 => Ok(text
            .parse::<i16>()
            .map_err(|_| bad())?
            .to_be_bytes()
            .to_vec()),
        23 => Ok(text
            .parse::<i32>()
            .map_err(|_| bad())?
            .to_be_bytes()
            .to_vec()),
        25 | 1042 | 1043 => Ok(value.to_vec()),
        2950 => {
            let hex = text.replace('-', "");
            if hex.len() != 32 || !hex.is_ascii() {
                return Err(bad());
            }
            (0..32)
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| bad()))
                .collect()
        }
        _ => Err(LedgerError::Protocol("unsupported binary cursor type")),
    }
}
impl SessionLedger {
    pub fn cursor_extended_frontend(
        &mut self,
        tag: u8,
        payload: &[u8],
        idle: bool,
    ) -> Result<Option<CursorMessages>, LedgerError> {
        let mut protocol = std::mem::take(&mut self.cursor_protocol);
        self.cursor_external_charge = protocol.bytes();
        let result = protocol.handle(self, tag, payload, idle);
        self.cursor_external_charge = 0;
        self.cursor_protocol = if result.is_ok() {
            protocol
        } else {
            CursorProtocol::default()
        };
        if result.is_ok()
            && let Err(error) = self.check_budget()
        {
            self.cursor_protocol = CursorProtocol::default();
            return Err(error);
        }
        result
    }
    fn cursor_description(&mut self, sql: &str) -> Result<Option<Option<Vec<u8>>>, LedgerError> {
        let parsed = match self.cache.parse(sql, self.state.parser_options) {
            Ok(p) => p,
            Err(ParseError::Syntax(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(stmts) = parsed.tree()["stmts"].as_array() else {
            return Ok(None);
        };
        if stmts.len() != 1 {
            return Ok(None);
        }
        let stmt = &stmts[0]["stmt"];
        if let Some(fetch) = stmt.get("FetchStmt") {
            let Some(cursor) = self.virtual_cursors.get(&string(fetch, "portalname")) else {
                return Ok(None);
            };
            return Ok(Some(if fetch["ismove"].as_bool() == Some(true) {
                None
            } else {
                Some(cursor.description().to_vec())
            }));
        }
        if let Some(close) = stmt.get("ClosePortalStmt") {
            let name = close["portalname"].as_str();
            if name.is_some_and(|n| self.virtual_cursors.contains_key(n))
                || (name.is_none()
                    && !self.virtual_cursors.is_empty()
                    && self.state.cursors.is_empty())
            {
                return Ok(Some(None));
            }
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn ledger() -> SessionLedger {
        let mut l = SessionLedger::new(1024 * 1024, 65536, Default::default());
        let mut d = vec![0, 1, b'x', 0];
        d.extend([0; 6]);
        d.extend(23u32.to_be_bytes());
        d.extend(4i16.to_be_bytes());
        d.extend((-1i32).to_be_bytes());
        d.extend([0, 0]);
        let rows = (1..=5)
            .map(|n| {
                let t = n.to_string();
                let mut row = vec![0, 1];
                row.extend((t.len() as i32).to_be_bytes());
                row.extend(t.as_bytes());
                row
            })
            .collect();
        l.install_cursor_snapshot("c".into(), CursorSnapshot::new(d, rows, 4096).unwrap())
            .unwrap();
        l
    }
    fn request(l: &mut SessionLedger, tag: u8, p: &[u8]) -> CursorMessages {
        l.cursor_extended_frontend(tag, p, true).unwrap().unwrap()
    }
    fn parse(l: &mut SessionLedger) {
        assert_eq!(
            request(l, b'P', b"st\0FETCH ALL FROM c\0\0\0"),
            vec![(b'1', vec![])]
        );
    }
    fn bind(l: &mut SessionLedger) {
        assert_eq!(
            request(l, b'B', b"p\0st\0\0\0\0\0\0\x01\0\x01"),
            vec![(b'2', vec![])]
        );
    }
    fn execute(l: &mut SessionLedger, n: i32) -> CursorMessages {
        let mut p = b"p\0".to_vec();
        p.extend(n.to_be_bytes());
        request(l, b'E', &p)
    }
    #[test]
    fn parse_bind_describe_binary_and_suspended_delivery_match_native() {
        let mut l = ledger();
        parse(&mut l);
        assert_eq!(request(&mut l, b'S', b""), vec![(b'Z', vec![b'I'])]);
        bind(&mut l);
        let describe = request(&mut l, b'D', b"Pp\0");
        assert_eq!(&describe[0].1[describe[0].1.len() - 2..], &[0, 1]);
        let first = execute(&mut l, 2);
        assert_eq!(first.len(), 3);
        assert_eq!(first.last(), Some(&(b's', vec![])));
        assert_eq!(&first[0].1[6..], &1i32.to_be_bytes());
        let second = execute(&mut l, 2);
        assert_eq!(second.last(), Some(&(b's', vec![])));
        let final_rows = execute(&mut l, 2);
        assert_eq!(final_rows.last().unwrap().1, b"FETCH 1\0");
        assert_eq!(execute(&mut l, 2), vec![(b'C', b"FETCH 0\0".to_vec())]);
        request(&mut l, b'S', b"");
        assert!(l.cursor_protocol.portals.is_empty());
        assert!(l.cursor_protocol.statements.contains_key("st"));
    }
    #[test]
    fn exact_limit_suspends_until_an_empty_final_execute() {
        let mut l = ledger();
        parse(&mut l);
        bind(&mut l);
        assert_eq!(execute(&mut l, 5).last(), Some(&(b's', vec![])));
        assert_eq!(execute(&mut l, 5), vec![(b'C', b"FETCH 0\0".to_vec())]);
    }
    #[test]
    fn binary_encodings_match_postgres_builtins() {
        assert_eq!(binary(16, b"t").unwrap(), vec![1]);
        assert_eq!(binary(21, b"-32768").unwrap(), i16::MIN.to_be_bytes());
        assert_eq!(
            binary(20, b"9223372036854775807").unwrap(),
            i64::MAX.to_be_bytes()
        );
        assert_eq!(
            binary(2950, b"00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            vec![
                0, 17, 34, 51, 68, 85, 102, 119, 136, 153, 170, 187, 204, 221, 238, 255
            ]
        );
        assert!(binary(2950, b"invalid").is_err());
    }
    #[test]
    fn closed_cursor_keeps_suspended_portal_descriptor_and_rows_alive() {
        let mut l = ledger();
        parse(&mut l);
        bind(&mut l);
        execute(&mut l, 2);
        let before = request(&mut l, b'D', b"Pp\0");
        request(&mut l, b'P', b"close\0CLOSE c\0\0\0");
        request(&mut l, b'B', b"q\0close\0\0\0\0\0\0\0");
        request(&mut l, b'E', b"q\0\0\0\0\0");
        assert!(!l.virtual_cursors.contains_key("c"));
        assert_eq!(request(&mut l, b'D', b"Pp\0"), before);
        assert_eq!(&execute(&mut l, 2)[0].1[6..], &3i32.to_be_bytes());
    }
    #[test]
    fn portal_budget_rejection_rewinds_unexecuted_fetch_and_drops_shared_refs() {
        let mut l = ledger();
        parse(&mut l);
        bind(&mut l);
        l.budget = l.cache.used_bytes()
            + l.virtual_cursors
                .values()
                .map(CursorSnapshot::bytes)
                .sum::<usize>()
            + l.cursor_protocol.bytes()
            + 64;
        let mut payload = b"p\0".to_vec();
        payload.extend(2i32.to_be_bytes());
        assert!(matches!(
            l.cursor_extended_frontend(b'E', &payload, true),
            Err(LedgerError::Budget)
        ));
        assert_eq!(l.virtual_cursors["c"].position(), 0);
        assert!(l.cursor_protocol.portals.is_empty());
        assert_eq!(l.cursor_external_charge, 0);
    }
    #[test]
    fn suspended_portal_rows_remain_stable_when_another_portal_repositions_cursor() {
        let mut l = ledger();
        parse(&mut l);
        bind(&mut l);
        execute(&mut l, 2);
        request(&mut l, b'P', b"move\0MOVE ABSOLUTE 0 FROM c\0\0\0");
        request(&mut l, b'B', b"q\0move\0\0\0\0\0\0\0");
        request(&mut l, b'E', b"q\0\0\0\0\0");
        assert_eq!(l.virtual_cursors["c"].position(), 0);
        let resumed = execute(&mut l, 2);
        assert_eq!(&resumed[0].1[6..], &3i32.to_be_bytes());
        assert_eq!(l.virtual_cursors["c"].position(), 0);
    }
    #[test]
    fn cycles_and_budgets_fail_closed_before_physical_forwarding() {
        let mut l = ledger();
        parse(&mut l);
        assert!(
            l.cursor_extended_frontend(b'Q', b"SELECT 1\0", true)
                .is_err()
        );
        let mut l = ledger();
        parse(&mut l);
        assert!(
            l.cursor_extended_frontend(b'B', b"bad\0st\0\0\0\0\0\0\x02\0\0\0\0", true)
                .is_err()
        );
        let mut l = ledger();
        parse(&mut l);
        assert!(
            l.cursor_extended_frontend(b'B', b"p\0st\0\0\0\0\0\0\0", false)
                .is_err()
        );
    }
    /// Mirrors `virtual_state_check.py::extended_closed_cursor_portal`, which
    /// cannot run its native comparison because the tested PostgreSQL fixture
    /// crashes on the suspended-CLOSE path. The proxy must service the CLOSE
    /// locally and keep the suspended portal's cached descriptor and rows alive.
    #[test]
    fn suspended_portal_survives_a_local_cursor_close_without_reaching_a_backend() {
        let mut l = ledger();
        parse(&mut l);
        bind(&mut l);
        let first = execute(&mut l, 2);
        assert_eq!(&first[0].1[6..], &1i32.to_be_bytes());
        assert_eq!(first.last(), Some(&(b's', vec![])));
        let before = request(&mut l, b'D', b"Pp\0");
        // Parse/Bind/Execute CLOSE while portal "p" is suspended.
        assert_eq!(
            request(&mut l, b'P', b"close\0CLOSE c\0\0\0"),
            vec![(b'1', vec![])]
        );
        assert_eq!(
            request(&mut l, b'B', b"q\0close\0\0\0\0\0\0\0"),
            vec![(b'2', vec![])]
        );
        assert_eq!(
            request(&mut l, b'E', b"q\0\0\0\0\0"),
            vec![(b'C', b"CLOSE CURSOR\0".to_vec())]
        );
        assert!(!l.virtual_cursors.contains_key("c"));
        // The suspended portal is unaffected and keeps delivering its snapshot.
        assert_eq!(request(&mut l, b'D', b"Pp\0"), before);
        let resumed = execute(&mut l, 2);
        assert_eq!(&resumed[0].1[6..], &3i32.to_be_bytes());
        assert_eq!(resumed.last(), Some(&(b's', vec![])));
        assert_eq!(
            execute(&mut l, 2).last(),
            Some(&(b'C', b"FETCH 1\0".to_vec()))
        );
        // Sync clears portals but the prepared virtual statement survives.
        assert_eq!(request(&mut l, b'S', b""), vec![(b'Z', vec![b'I'])]);
        assert!(l.cursor_protocol.portals.is_empty());
        assert!(l.cursor_protocol.statements.contains_key("st"));
    }
}
