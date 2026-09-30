//! Bounded, immutable text snapshots of pristine SCROLL WITH HOLD cursors.
use super::*;
use std::sync::Arc;
pub type CursorMessages = Vec<(u8, Vec<u8>)>;
#[derive(Clone)]
pub struct CursorSnapshot {
    description: Vec<u8>,
    rows: Vec<Arc<[u8]>>,
    position: i64,
    charge: usize,
}
impl CursorSnapshot {
    /// Only output types whose text representation does not depend on session GUCs.
    pub fn new(description: Vec<u8>, rows: Vec<Vec<u8>>, limit: usize) -> Option<Self> {
        let count = u16::from_be_bytes(description.get(..2)?.try_into().ok()?) as usize;
        let mut rest = &description[2..];
        for _ in 0..count {
            let end = rest.iter().position(|b| *b == 0)?;
            rest = rest.get(end + 1..)?;
            let field = rest.get(..18)?;
            let oid = u32::from_be_bytes(field[6..10].try_into().ok()?);
            if !matches!(oid, 16 | 20 | 21 | 23 | 25 | 1042 | 1043 | 2950)
                || field[16..18] != [0, 0]
            {
                return None;
            }
            rest = &rest[18..];
        }
        if !rest.is_empty() {
            return None;
        }
        let rows: Vec<Arc<[u8]>> = rows
            .into_iter()
            .map(|row| Arc::from(row.into_boxed_slice()))
            .collect();
        let charge = description
            .capacity()
            .checked_add(rows.capacity() * std::mem::size_of::<Arc<[u8]>>())?
            .checked_add(
                rows.iter()
                    .map(|r| r.len() + 2 * std::mem::size_of::<usize>())
                    .sum::<usize>(),
            )?
            .checked_add(256)?;
        if charge > limit {
            return None;
        }
        Some(Self {
            description,
            rows,
            position: 0,
            charge,
        })
    }
    pub(crate) fn description(&self) -> &[u8] {
        &self.description
    }
    pub fn bytes(&self) -> usize {
        self.charge
    }
    fn fetch(&mut self, node: &Value) -> Result<CursorMessages, LedgerError> {
        let reply = self.fetch_refs(node)?;
        let mut messages = Vec::new();
        if let Some(d) = reply.description {
            messages.push((b'T', d));
        }
        for row in reply.rows {
            messages.push((b'D', row.to_vec()));
        }
        messages.push((b'C', reply.command));
        Ok(messages)
    }
    pub(crate) fn position(&self) -> i64 {
        self.position
    }
    pub(crate) fn set_position(&mut self, position: i64) {
        self.position = position;
    }
    fn fetch_refs(&mut self, node: &Value) -> Result<CursorReply, LedgerError> {
        let direction = node
            .get("direction")
            .and_then(Value::as_str)
            .unwrap_or("FETCH_FORWARD");
        let amount = node.get("howMany").and_then(Value::as_i64).unwrap_or(0);
        let movement = node.get("ismove").and_then(Value::as_bool).unwrap_or(false);
        let n = self.rows.len() as i64;
        let mut indices = Vec::new();
        match direction {
            "FETCH_FORWARD" | "FETCH_BACKWARD" => {
                let step = if direction == "FETCH_FORWARD" { 1 } else { -1 }
                    * if amount < 0 { -1 } else { 1 };
                let requested = amount.unsigned_abs().min(n as u64 + 1);
                if amount == 0 {
                    if self.position > 0 && self.position <= n {
                        indices.push(self.position as usize - 1);
                    }
                } else {
                    for _ in 0..requested {
                        self.position = (self.position + step).clamp(0, n + 1);
                        if self.position == 0 || self.position == n + 1 {
                            break;
                        }
                        indices.push(self.position as usize - 1);
                    }
                }
            }
            "FETCH_ABSOLUTE" | "FETCH_RELATIVE" => {
                let target = if direction == "FETCH_RELATIVE" {
                    self.position.saturating_add(amount)
                } else if amount < 0 {
                    n.saturating_add(amount).saturating_add(1)
                } else {
                    amount
                };
                self.position = target.clamp(0, n + 1);
                if self.position > 0 && self.position <= n {
                    indices.push(self.position as usize - 1);
                }
            }
            _ => {
                return Err(LedgerError::Protocol(
                    "unsupported virtual cursor direction",
                ));
            }
        }
        Ok(CursorReply {
            description: if movement {
                None
            } else {
                Some(self.description.clone())
            },
            rows: if movement {
                VecDeque::new()
            } else {
                indices.iter().map(|i| Arc::clone(&self.rows[*i])).collect()
            },
            command: format!(
                "{} {}\0",
                if movement { "MOVE" } else { "FETCH" },
                indices.len()
            )
            .into_bytes(),
        })
    }
}
pub(crate) struct CursorReply {
    pub(crate) description: Option<Vec<u8>>,
    pub(crate) rows: VecDeque<Arc<[u8]>>,
    pub(crate) command: Vec<u8>,
}
impl SessionLedger {
    pub(crate) fn cursor_reply(
        &mut self,
        sql: &str,
    ) -> Result<(CursorReply, Option<(String, i64)>), LedgerError> {
        let parsed = self.cache.parse(sql, self.state.parser_options)?;
        let stmts = parsed.tree()["stmts"]
            .as_array()
            .ok_or(LedgerError::Protocol("invalid cursor query"))?;
        if stmts.len() != 1 {
            return Err(LedgerError::Protocol(
                "cursor Execute requires one statement",
            ));
        }
        let stmt = &stmts[0]["stmt"];
        if let Some(node) = stmt.get("FetchStmt") {
            let name = string(node, "portalname");
            let cursor = self
                .virtual_cursors
                .get_mut(&name)
                .ok_or(LedgerError::Protocol("virtual cursor no longer exists"))?;
            let position = cursor.position();
            return Ok((cursor.fetch_refs(node)?, Some((name, position))));
        }
        if let Some(node) = stmt.get("ClosePortalStmt")
            && (node["portalname"]
                .as_str()
                .is_some_and(|name| self.virtual_cursors.contains_key(name))
                || (node["portalname"].is_null()
                    && !self.virtual_cursors.is_empty()
                    && self.state.cursors.is_empty()))
        {
            return Ok((
                CursorReply {
                    description: None,
                    rows: VecDeque::new(),
                    command: b"CLOSE CURSOR\0".to_vec(),
                },
                None,
            ));
        }
        Err(LedgerError::Protocol("virtual cursor no longer exists"))
    }

    pub fn parse_options(&self) -> ParseOptions {
        self.state.parser_options
    }
    pub fn cursor_snapshot_limit(&self) -> usize {
        self.budget / 2
    }
    pub fn retain_native_cursor(&mut self, name: &str) {
        self.eligible_cursors.remove(name);
    }
    pub fn cursor_candidates(&self) -> Vec<String> {
        if self.permanent_affinity
            || self.uncertain_affinity
            || self.advisory
            || self.state.opaque
            || !self.state.listeners.is_empty()
            || !self.state.temps.is_empty()
            || !self.pending.is_empty()
            || !self.prepared.is_empty()
            || !self.sql_prepared.is_empty()
        {
            return Vec::new();
        }
        self.eligible_cursors
            .iter()
            .filter(|name| self.state.cursors.get(*name) == Some(&true))
            .cloned()
            .collect()
    }
    pub fn install_cursor_snapshot(
        &mut self,
        name: String,
        snapshot: CursorSnapshot,
    ) -> Result<(), LedgerError> {
        self.virtual_cursors.insert(name.clone(), snapshot);
        if let Err(error) = self.check_budget() {
            self.virtual_cursors.remove(&name);
            return Err(error);
        }
        self.state.cursors.remove(&name);
        self.eligible_cursors.remove(&name);
        Ok(())
    }
    /// Call before frontend(), only at an idle protocol boundary. Extended or multi-
    /// statement virtual cursor access is explicitly unsupported, rather than relayed
    /// to a backend where its physical cursor no longer exists.
    pub fn virtual_cursor_request(
        &mut self,
        tag: u8,
        payload: &[u8],
        idle: bool,
    ) -> Result<Option<CursorMessages>, LedgerError> {
        if self.virtual_cursors.is_empty() || !matches!(tag, b'Q' | b'P') {
            return Ok(None);
        }
        let (sql, _) = if tag == b'P' {
            let (_, rest) = cstring(payload)?;
            cstring(rest)?
        } else {
            cstring(payload)?
        };
        let parsed = match self.cache.parse(&sql, self.state.parser_options) {
            Ok(parsed) => parsed,
            Err(ParseError::Syntax(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stmts = parsed
            .tree()
            .get("stmts")
            .and_then(Value::as_array)
            .ok_or(LedgerError::Protocol("invalid cursor query"))?;
        let refers = stmts.iter().any(|raw| {
            let stmt = &raw["stmt"];
            ["FetchStmt", "ClosePortalStmt", "DeclareCursorStmt"]
                .iter()
                .any(|kind| {
                    stmt.get(*kind).is_some_and(|node| {
                        node.get("portalname")
                            .and_then(Value::as_str)
                            .is_some_and(|name| self.virtual_cursors.contains_key(name))
                            || (*kind == "ClosePortalStmt" && node.get("portalname").is_none())
                    })
                })
        });
        if !refers {
            return Ok(None);
        }
        if tag != b'Q' || !idle || !self.pending.is_empty() || stmts.len() != 1 {
            return Err(LedgerError::Protocol(
                "virtual cursors require a single simple query at an idle boundary",
            ));
        }
        let stmt = &stmts[0]["stmt"];
        if let Some(node) = stmt.get("FetchStmt") {
            let name = string(node, "portalname");
            return self
                .virtual_cursors
                .get_mut(&name)
                .expect("known virtual cursor")
                .fetch(node)
                .map(Some);
        }
        if let Some(node) = stmt.get("ClosePortalStmt") {
            if node.get("portalname").is_none() && !self.state.cursors.is_empty() {
                return Ok(None);
            }
            return Ok(Some(vec![(b'C', b"CLOSE CURSOR\0".to_vec())]));
        }
        Err(LedgerError::Protocol("virtual cursor already exists"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> CursorSnapshot {
        let mut desc = vec![0, 1, b'x', 0];
        desc.extend([0; 6]);
        desc.extend(23u32.to_be_bytes());
        desc.extend(4i16.to_be_bytes());
        desc.extend((-1i32).to_be_bytes());
        desc.extend([0, 0]);
        CursorSnapshot::new(
            desc,
            vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
            1024,
        )
        .unwrap()
    }
    #[test]
    fn scroll_positions_and_bounds() {
        let mut c = snapshot();
        let q = |direction: &str, n| serde_json::json!({"direction":direction,"howMany":n});
        assert_eq!(
            c.fetch(&q("FETCH_FORWARD", 2)).unwrap().last().unwrap().1,
            b"FETCH 2\0"
        );
        assert_eq!(c.fetch(&q("FETCH_BACKWARD", 1)).unwrap()[1].1, b"a");
        assert_eq!(c.fetch(&q("FETCH_ABSOLUTE", -1)).unwrap()[1].1, b"c");
        assert_eq!(
            c.fetch(&q("FETCH_FORWARD", 99)).unwrap().last().unwrap().1,
            b"FETCH 0\0"
        );
        assert_eq!(c.fetch(&q("FETCH_BACKWARD", 1)).unwrap()[1].1, b"c");
    }
    #[test]
    fn omitted_zero_parser_fields_follow_postgres_positions() {
        let mut ledger = SessionLedger::new(1024 * 1024, 65536, Default::default());
        ledger
            .install_cursor_snapshot("c".into(), snapshot())
            .unwrap();
        let request = |l: &mut SessionLedger, sql: &str| {
            let mut p = sql.as_bytes().to_vec();
            p.push(0);
            l.virtual_cursor_request(b'Q', &p, true).unwrap().unwrap()
        };
        assert_eq!(
            request(&mut ledger, "MOVE ABSOLUTE 0 FROM c")
                .last()
                .unwrap()
                .1,
            b"MOVE 0\0"
        );
        assert_eq!(request(&mut ledger, "FETCH NEXT FROM c")[1].1, b"a");
        assert_eq!(request(&mut ledger, "FETCH FORWARD 0 FROM c")[1].1, b"a");
        assert_eq!(request(&mut ledger, "FETCH NEXT FROM c")[1].1, b"b");
    }
    #[test]
    fn cursor_eligibility_requires_pristine_scroll_hold_and_no_other_affinity() {
        fn query(l: &mut SessionLedger, sql: &str, commands: &[&str], status: u8) {
            let mut p = sql.as_bytes().to_vec();
            p.push(0);
            l.frontend(b'Q', &p).unwrap();
            for c in commands {
                let mut p = c.as_bytes().to_vec();
                p.push(0);
                l.backend(b'C', &p).unwrap();
            }
            l.backend(b'Z', &[status]).unwrap();
        }
        let mut l = SessionLedger::new(1024 * 1024, 65536, Default::default());
        query(&mut l, "BEGIN", &["BEGIN"], b'T');
        query(
            &mut l,
            "DECLARE held SCROLL CURSOR WITH HOLD FOR SELECT 1",
            &["DECLARE CURSOR"],
            b'T',
        );
        query(&mut l, "COMMIT", &["COMMIT"], b'I');
        assert_eq!(l.cursor_candidates(), vec!["held"]);
        // Even a failed FETCH cannot certify the portal is still pristine.
        let mut p = b"FETCH ALL FROM held".to_vec();
        p.push(0);
        l.frontend(b'Q', &p).unwrap();
        l.backend(b'E', &[]).unwrap();
        l.backend(b'Z', b"I").unwrap();
        assert!(l.cursor_candidates().is_empty());
        query(&mut l, "DISCARD ALL", &["DISCARD ALL"], b'I');
        query(
            &mut l,
            "BEGIN; DECLARE rolled SCROLL CURSOR WITH HOLD FOR SELECT 1",
            &["BEGIN", "DECLARE CURSOR"],
            b'T',
        );
        query(&mut l, "ROLLBACK", &["ROLLBACK"], b'I');
        assert!(l.eligible_cursors.is_empty());
        query(
            &mut l,
            "BEGIN; DECLARE noscroll NO SCROLL CURSOR WITH HOLD FOR SELECT 1; COMMIT",
            &["BEGIN", "DECLARE CURSOR", "COMMIT"],
            b'I',
        );
        assert!(l.cursor_candidates().is_empty());
    }
    #[test]
    fn budgets_and_output_types_are_checked() {
        let c = snapshot();
        assert!(
            CursorSnapshot::new(
                c.description.clone(),
                c.rows.iter().map(|r| r.to_vec()).collect(),
                1
            )
            .is_none()
        );
        let mut d = c.description;
        d[10..14].copy_from_slice(&1184u32.to_be_bytes());
        assert!(CursorSnapshot::new(d, vec![], 1024).is_none());
    }
}
