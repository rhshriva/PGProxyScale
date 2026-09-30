//! A client-intent ledger independent of sockets and the proxy runtime.
#![forbid(unsafe_code)]
use pgproxy_parser::{ParseCache, ParseError, ParseOptions};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("session state exceeds its memory budget")]
    Budget,
    #[error("invalid frontend message: {0}")]
    Protocol(&'static str),
    #[error(transparent)]
    Parse(#[from] ParseError),
}
mod cursor;
mod cursor_protocol;
pub use cursor::CursorSnapshot;
type Settings = Vec<(String, String)>;
#[derive(Clone, Default)]
struct State {
    settings: Settings,
    parser_options: ParseOptions,
    persistent_parser_options: ParseOptions,
    listeners: BTreeSet<String>,
    cursors: BTreeMap<String, bool>,
    temps: BTreeSet<String>,
    opaque: bool,
    local: bool,
    local_affects_parse: bool,
}
#[derive(Clone)]
struct Prepared {
    name: String,
    sql: String,
    payload: Option<Vec<u8>>,
    context: Settings,
}
#[derive(Clone)]
enum Action {
    None,
    Set(String, String),
    Reset(String, bool),
    ParserSet(String, String, Option<bool>),
    LocalParserSet(String, Option<bool>),
    ResetAll,
    Begin,
    Commit,
    Rollback,
    Savepoint(String),
    RollbackTo(String),
    Release(String),
    PrepareSql(Prepared),
    ExecuteSql(String),
    Deallocate(Option<String>),
    DiscardAll,
    Listen(String),
    Unlisten(Option<String>),
    Cursor(String, bool, bool),
    TouchCursor(String),
    CloseCursor(Option<String>),
    Temp(String),
    DropTemp(Vec<String>),
    Pin,
    Local(String),
    Advisory,
    UnlockAll,
}
enum Pending {
    Parse(Prepared),
    Bind(String, String),
    CloseStatement(String),
    ClosePortal(String),
    Execute(VecDeque<Action>),
    Query(VecDeque<Action>),
    Sync,
}
#[derive(Debug)]
pub enum RestoreCommand {
    Query(String),
    Parse(Vec<u8>),
}
/// Only confirmed backend completions mutate the image. Session-scoped server objects
/// that cannot yet be virtualised explicitly retain ownership instead of being lost.
pub struct SessionLedger {
    state: State,
    eligible_cursors: BTreeSet<String>,
    virtual_cursors: BTreeMap<String, CursorSnapshot>,
    cursor_protocol: cursor_protocol::CursorProtocol,
    cursor_external_charge: usize,
    startup_defaults: Settings,
    checkpoint: Option<State>,
    savepoints: Vec<(String, State)>,
    prepared: BTreeMap<String, Prepared>,
    sql_prepared: BTreeMap<String, Prepared>,
    portals: BTreeMap<String, String>,
    pending: VecDeque<Pending>,
    cache: ParseCache,
    options: ParseOptions,
    budget: usize,
    error: bool,
    advisory: bool,
    permanent_affinity: bool,
    pending_startup_restore: bool,
    uncertain_affinity: bool,
}
impl SessionLedger {
    pub fn new(budget: usize, max_sql: usize, options: ParseOptions) -> Self {
        Self {
            state: State {
                parser_options: options,
                persistent_parser_options: options,
                ..State::default()
            },
            eligible_cursors: BTreeSet::new(),
            virtual_cursors: BTreeMap::new(),
            cursor_protocol: Default::default(),
            cursor_external_charge: 0,
            startup_defaults: Vec::new(),
            checkpoint: None,
            savepoints: Vec::new(),
            prepared: BTreeMap::new(),
            sql_prepared: BTreeMap::new(),
            portals: BTreeMap::new(),
            pending: VecDeque::new(),
            cache: ParseCache::new(budget / 2, max_sql),
            options,
            budget,
            error: false,
            advisory: false,
            permanent_affinity: false,
            pending_startup_restore: false,
            uncertain_affinity: false,
        }
    }
    /// Set the negotiated backend major before any SQL is parsed or forwarded.
    /// The vendored grammar is PostgreSQL 18; this version tags cache/fingerprints
    /// and does not claim a separate grammar implementation for older servers.
    pub fn set_backend_major(&mut self, major: u16) -> Result<(), LedgerError> {
        if !(14..=18).contains(&major) {
            return Err(ParseError::UnsupportedVersion(major).into());
        }
        if self.cache.used_bytes() != 0
            || !self.pending.is_empty()
            || !self.prepared.is_empty()
            || !self.sql_prepared.is_empty()
        {
            return Err(LedgerError::Protocol(
                "backend version must be set before SQL",
            ));
        }
        self.options.backend_major = major;
        self.state.parser_options.backend_major = major;
        self.state.persistent_parser_options.backend_major = major;
        Ok(())
    }
    /// Session pooling keeps affinity even when the client executes DISCARD ALL.
    pub fn retain_backend_for_session(&mut self) {
        self.permanent_affinity = true;
    }
    pub fn is_pinned(&self) -> bool {
        self.permanent_affinity
            || self.uncertain_affinity
            || self.advisory
            || self
                .prepared
                .get("")
                .is_some_and(|p| p.context != self.state.settings)
            || self.state.opaque
            || !self.state.listeners.is_empty()
            || !self.state.cursors.is_empty()
            || !self.state.temps.is_empty()
    }
    pub fn pin_reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.permanent_affinity {
            reasons.push("session pooling");
        }
        if self.advisory {
            reasons.push("session advisory lock");
        }
        if self.uncertain_affinity {
            reasons.push("potential nontransactional function effect");
        }
        if self.state.opaque {
            reasons.push("opaque or parser-affecting session state");
        }
        if !self.state.listeners.is_empty() {
            reasons.push("LISTEN subscription");
        }
        if !self.state.cursors.is_empty() {
            reasons.push("cursor");
        }
        if !self.state.temps.is_empty() {
            reasons.push("temporary table");
        }
        reasons
    }
    fn check_budget(&self) -> Result<(), LedgerError> {
        let prepared_bytes: usize = self
            .prepared
            .values()
            .chain(self.sql_prepared.values())
            .map(|p| {
                p.name.len()
                    + p.sql.len()
                    + p.payload.as_ref().map_or(0, Vec::len)
                    + p.context
                        .iter()
                        .map(|(k, v)| k.len() + v.len() + 128)
                        .sum::<usize>()
                    + 256
            })
            .sum();
        let state_charge = |s: &State| {
            s.settings
                .iter()
                .map(|(k, v)| k.len() + v.len() + 128)
                .sum::<usize>()
                + s.listeners
                    .iter()
                    .chain(s.temps.iter())
                    .map(|k| k.len() + 128)
                    .sum::<usize>()
                + s.cursors.keys().map(|k| k.len() + 128).sum::<usize>()
        };
        let pending_charge: usize = self
            .pending
            .iter()
            .map(|p| match p {
                Pending::Parse(p) => {
                    p.sql.len()
                        + p.name.len()
                        + p.payload.as_ref().map_or(0, Vec::len)
                        + p.context
                            .iter()
                            .map(|(k, v)| k.len() + v.len() + 128)
                            .sum::<usize>()
                        + 256
                }
                Pending::Query(actions) | Pending::Execute(actions) => {
                    actions.iter().map(action_charge).sum()
                }
                Pending::Bind(portal, statement) => portal.len() + statement.len() + 256,
                Pending::CloseStatement(name) | Pending::ClosePortal(name) => name.len() + 256,
                _ => 256,
            })
            .sum();
        if self.pending.len() > 4096
            || self.savepoints.len() > 64
            || self
                .startup_defaults
                .iter()
                .map(|(k, v)| k.len() + v.len() + 128)
                .sum::<usize>()
                + prepared_bytes
                + state_charge(&self.state)
                + self.checkpoint.as_ref().map_or(0, state_charge)
                + self
                    .savepoints
                    .iter()
                    .map(|(_, s)| state_charge(s))
                    .sum::<usize>()
                + pending_charge
                + self.cursor_protocol.bytes()
                + self.cursor_external_charge
                + self
                    .eligible_cursors
                    .iter()
                    .map(|name| name.len() + 128)
                    .sum::<usize>()
                + self
                    .virtual_cursors
                    .values()
                    .map(CursorSnapshot::bytes)
                    .sum::<usize>()
                + self.cache.used_bytes()
                + self
                    .portals
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 128)
                    .sum::<usize>()
                > self.budget
        {
            Err(LedgerError::Budget)
        } else {
            Ok(())
        }
    }
    /// Restore settings and prepared statements on a clean backend, preserving each
    /// statement's parse-time GUC context. The caller suppresses restore responses.
    pub fn restore(&self) -> Vec<RestoreCommand> {
        let mut commands = Vec::new();
        let mut context = Settings::new();
        for prepared in self
            .sql_prepared
            .values()
            .chain(self.prepared.values().filter(|p| !p.name.is_empty()))
        {
            if context != prepared.context {
                if context
                    .iter()
                    .chain(prepared.context.iter())
                    .any(|(name, _)| name == "role")
                {
                    commands.push(RestoreCommand::Query("RESET ROLE".into()));
                }
                commands.push(RestoreCommand::Query("RESET ALL".into()));
                for (_, sql) in &prepared.context {
                    commands.push(RestoreCommand::Query(sql.clone()));
                }
                context = prepared.context.clone();
            }
            if let Some(payload) = &prepared.payload {
                commands.push(RestoreCommand::Parse(payload.clone()));
            } else {
                commands.push(RestoreCommand::Query(prepared.sql.clone()));
            }
        }
        if context != self.state.settings {
            if context
                .iter()
                .chain(self.state.settings.iter())
                .any(|(name, _)| name == "role")
            {
                commands.push(RestoreCommand::Query("RESET ROLE".into()));
            }
            commands.push(RestoreCommand::Query("RESET ALL".into()));
            for (_, sql) in &self.state.settings {
                commands.push(RestoreCommand::Query(sql.clone()));
            }
        }
        if let Some(unnamed) = self.prepared.get("")
            && let Some(payload) = &unnamed.payload
        {
            commands.push(RestoreCommand::Parse(payload.clone()));
        }
        commands
    }
    /// A startup setting is quoted as data, never concatenated as executable SQL.
    pub fn startup_setting(&mut self, name: &str, value: &str) -> Result<(), LedgerError> {
        if name.is_empty() || name.contains('\0') || value.contains('\0') {
            return Err(LedgerError::Protocol("invalid startup setting"));
        }
        let quoted_name = name.replace('"', "\"\"");
        if let Some(boolean) = guc_boolean(value) {
            match name {
                "standard_conforming_strings" => {
                    self.options.standard_conforming_strings = boolean;
                    self.state.parser_options.standard_conforming_strings = boolean;
                    self.state
                        .persistent_parser_options
                        .standard_conforming_strings = boolean;
                }
                "backslash_quote" => {
                    self.options.backslash_quote = boolean;
                    self.state.parser_options.backslash_quote = boolean;
                    self.state.persistent_parser_options.backslash_quote = boolean;
                }
                _ => {}
            }
        }
        let value = value.replace('\\', "\\\\").replace('\'', "\\'");
        let sql = format!("SET \"{quoted_name}\" TO E'{value}'");
        upsert(&mut self.startup_defaults, name.into(), sql.clone());
        upsert(&mut self.state.settings, name.into(), sql);
        if matches!(
            name,
            "standard_conforming_strings" | "backslash_quote" | "client_encoding"
        ) {
            self.state.opaque = true;
        }
        self.check_budget()
    }
    /// Adapt RESET to the client's startup defaults before sending it to a backend.
    /// Call `frontend` with the original payload first, so completions retain original
    /// client intent. The returned payload is transport-only; policy must inspect the
    /// original SQL. RESET ALL uses a single trusted PL/pgSQL DO statement so it also
    /// works in the extended protocol. PostgreSQL's standard plpgsql language is required.
    pub fn rewrite_frontend(
        &mut self,
        tag: u8,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, LedgerError> {
        let (name, sql, rest) = match tag {
            b'Q' => {
                let (sql, rest) = cstring(payload)?;
                (None, sql, rest)
            }
            b'P' => {
                let (name, rest) = cstring(payload)?;
                let (sql, rest) = cstring(rest)?;
                (Some(name), sql, rest)
            }
            _ => return Ok(None),
        };
        let Some(sql) = self.rewrite_query(&sql)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        if let Some(name) = name {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes.extend_from_slice(sql.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(rest);
        if bytes.len() > self.budget {
            return Err(LedgerError::Budget);
        }
        Ok(Some(bytes))
    }
    /// Statements needed after a backend executes DISCARD ALL for this client.
    /// Suppress these responses and complete them before processing its next request.
    /// Drain the startup replay request only after an idle ReadyForQuery.
    pub fn take_startup_restore(&mut self) -> Vec<RestoreCommand> {
        if std::mem::take(&mut self.pending_startup_restore) {
            self.startup_restore()
        } else {
            Vec::new()
        }
    }
    pub fn startup_restore(&self) -> Vec<RestoreCommand> {
        self.startup_defaults
            .iter()
            .map(|(_, sql)| RestoreCommand::Query(sql.clone()))
            .collect()
    }
    pub fn rewrite_query(&mut self, sql: &str) -> Result<Option<String>, LedgerError> {
        if self.startup_defaults.is_empty() {
            return Ok(None);
        }
        let parsed = match self.cache.parse(sql, self.state.parser_options) {
            Ok(parsed) => parsed,
            Err(ParseError::Syntax(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut replacements = Vec::new();
        for raw in parsed
            .tree()
            .get("stmts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(set) = raw.get("stmt").and_then(|s| s.get("VariableSetStmt")) else {
                continue;
            };
            if set.get("is_local").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let kind = string(set, "kind");
            let replacement = if kind == "VAR_RESET_ALL" {
                let body = format!(
                    "BEGIN RESET ALL; {}; END",
                    self.startup_defaults
                        .iter()
                        .map(|(_, sql)| sql.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                let mut delimiter = "$pgproxy_reset$".to_owned();
                while body.contains(&delimiter) {
                    delimiter.insert(delimiter.len() - 1, '_');
                }
                Some(format!("DO {delimiter}{body}{delimiter}"))
            } else if matches!(kind.as_str(), "VAR_RESET" | "VAR_SET_DEFAULT") {
                let name = string(set, "name");
                self.startup_defaults
                    .iter()
                    .find(|(key, _)| key == &name)
                    .map(|(_, sql)| sql.clone())
            } else {
                None
            };
            if let Some(replacement) = replacement {
                let start = raw
                    .get("stmt_location")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                let length = raw.get("stmt_len").and_then(Value::as_u64).unwrap_or(0) as usize;
                let end = if length == 0 {
                    sql.len()
                } else {
                    start + length
                };
                if sql.get(start..end).is_none() {
                    return Err(LedgerError::Protocol("invalid SQL locations"));
                }
                replacements.push((start, end, replacement));
            }
        }
        if replacements.is_empty() {
            return Ok(None);
        }
        let mut rewritten = sql.to_owned();
        for (start, end, replacement) in replacements.into_iter().rev() {
            rewritten.replace_range(start..end, &replacement);
        }
        if rewritten.len() > self.budget {
            return Err(LedgerError::Budget);
        }
        Ok(Some(rewritten))
    }
    // A FETCH may move a portal before an execution error. Treat every attempted
    // access as non-pristine, including a DECLARE still awaiting completion.
    fn guard_cursor_access(&mut self, actions: &mut VecDeque<Action>) {
        let touched: BTreeSet<_> = actions
            .iter()
            .filter_map(|a| match a {
                Action::TouchCursor(name) => Some(name.clone()),
                _ => None,
            })
            .collect();
        for name in &touched {
            self.eligible_cursors.remove(name);
        }
        let invalidate = |actions: &mut VecDeque<Action>| {
            for action in actions {
                if let Action::Cursor(name, _, eligible) = action
                    && touched.contains(name)
                {
                    *eligible = false;
                }
            }
        };
        invalidate(actions);
        for pending in &mut self.pending {
            match pending {
                Pending::Query(actions) | Pending::Execute(actions) => invalidate(actions),
                _ => {}
            }
        }
    }
    fn actions(&mut self, sql: &str) -> Result<VecDeque<Action>, LedgerError> {
        let parsed = match self.cache.parse(sql, self.state.parser_options) {
            Ok(parsed) => parsed,
            Err(ParseError::Syntax(_)) => return Ok(VecDeque::from([Action::Pin])),
            Err(error) => return Err(error.into()),
        };
        let mut actions = VecDeque::new();
        let Some(stmts) = parsed.tree().get("stmts").and_then(Value::as_array) else {
            return Ok(actions);
        };
        for raw in stmts {
            let location = raw
                .get("stmt_location")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize;
            let length = raw.get("stmt_len").and_then(Value::as_u64).unwrap_or(0) as usize;
            let statement_sql = sql
                .get(
                    location..if length == 0 {
                        sql.len()
                    } else {
                        location + length
                    },
                )
                .ok_or(LedgerError::Protocol("invalid SQL locations"))?
                .trim()
                .to_string();
            let stmt = raw
                .get("stmt")
                .ok_or(LedgerError::Protocol("invalid parse tree"))?;
            actions.push_back(classify(stmt, &statement_sql, &self.state.settings));
        }
        Ok(actions)
    }
    /// A startup-resetting DISCARD needs a response boundary before another request.
    /// Extended executions must still admit Flush and Sync until Sync is enqueued.
    pub fn awaiting_discard_sync(&self) -> bool {
        if self.startup_defaults.is_empty() {
            return false;
        }
        (self.pending_startup_restore && !self.pending.iter().any(|p| matches!(p, Pending::Query(_) | Pending::Sync))) || self.pending.iter().any(|p| matches!(p, Pending::Execute(actions) if actions.iter().any(|a| matches!(a, Action::DiscardAll))))
    }
    pub fn frontend_barrier(&self) -> bool {
        if self.startup_defaults.is_empty() {
            return false;
        }
        if self.pending_startup_restore {
            return self
                .pending
                .iter()
                .any(|p| matches!(p, Pending::Query(_) | Pending::Sync));
        }
        let mut discard_execute = false;
        for pending in &self.pending {
            match pending {
                Pending::Query(actions)
                    if actions.iter().any(|a| matches!(a, Action::DiscardAll)) =>
                {
                    return true;
                }
                Pending::Execute(actions)
                    if actions.iter().any(|a| matches!(a, Action::DiscardAll)) =>
                {
                    discard_execute = true
                }
                Pending::Sync if discard_execute => return true,
                _ => {}
            }
        }
        false
    }
    fn guard_nontransactional_effects(&mut self, actions: &VecDeque<Action>) {
        // A SELECT can acquire a session lock or call a stateful function before
        // another expression fails. CommandComplete alone cannot prove absence of
        // those effects. Ownership must already be protected before forwarding.
        for action in actions {
            match action {
                Action::Pin => self.uncertain_affinity = true,
                Action::Advisory => self.advisory = true,
                Action::ExecuteSql(name) => {
                    if let Some(prepared) = self.sql_prepared.get(name)
                        && let Ok(parsed) =
                            self.cache.parse(&prepared.sql, self.state.parser_options)
                        && let Some(query) = parsed
                            .statements()
                            .next()
                            .and_then(|s| s.get("PrepareStmt"))
                            .and_then(|s| s.get("query"))
                    {
                        let effect = classify(query, "", &self.state.settings);
                        match effect {
                            Action::Pin => self.uncertain_affinity = true,
                            Action::Advisory => self.advisory = true,
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    pub fn frontend(&mut self, tag: u8, payload: &[u8]) -> Result<(), LedgerError> {
        match tag {
            b'Q' => {
                let (sql, rest) = cstring(payload)?;
                if !rest.is_empty() {
                    return Err(LedgerError::Protocol("trailing Query bytes"));
                }
                self.prepared.remove("");
                let mut actions = self.actions(&sql)?;
                self.guard_cursor_access(&mut actions);
                self.guard_nontransactional_effects(&actions);
                self.pending.push_back(Pending::Query(actions));
            }
            b'P' => {
                let (name, rest) = cstring(payload)?;
                let (sql, rest) = cstring(rest)?;
                if rest.len() < 2 {
                    return Err(LedgerError::Protocol("missing Parse type count"));
                }
                let count = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                if rest.len() != 2 + count * 4 {
                    return Err(LedgerError::Protocol("invalid Parse type list"));
                }
                let actions = self.actions(&sql)?; // Enforce parser/input budgets before forwarding.
                for action in actions {
                    if let Action::TouchCursor(name) = action {
                        self.eligible_cursors.remove(&name);
                    }
                }
                if name.is_empty() {
                    self.prepared.remove("");
                }
                if self.state.local_affects_parse {
                    self.state.opaque = true;
                }
                let rewritten_payload = self
                    .rewrite_frontend(tag, payload)?
                    .unwrap_or_else(|| payload.to_vec());
                self.pending.push_back(Pending::Parse(Prepared {
                    name,
                    sql,
                    payload: Some(rewritten_payload),
                    context: self.state.settings.clone(),
                }));
            }
            b'B' => {
                let (portal, rest) = cstring(payload)?;
                let (statement, _) = cstring(rest)?;
                self.pending.push_back(Pending::Bind(portal, statement));
            }
            b'E' => {
                let (portal, rest) = cstring(payload)?;
                if rest.len() != 4 {
                    return Err(LedgerError::Protocol("invalid Execute"));
                }
                let statement = self
                    .pending
                    .iter()
                    .rev()
                    .find_map(|p| {
                        if let Pending::Bind(name, statement) = p {
                            (name == &portal).then(|| statement.clone())
                        } else {
                            None
                        }
                    })
                    .or_else(|| self.portals.get(&portal).cloned());
                let prepared = statement.and_then(|name| {
                    self.pending
                        .iter()
                        .rev()
                        .find_map(|p| {
                            if let Pending::Parse(p) = p {
                                (p.name == name).then(|| p.clone())
                            } else {
                                None
                            }
                        })
                        .or_else(|| self.prepared.get(&name).cloned())
                });
                let actions = if let Some(p) = prepared {
                    self.actions(&p.sql)?
                } else {
                    VecDeque::from([Action::None])
                };
                self.guard_nontransactional_effects(&actions);
                self.pending.push_back(Pending::Execute(actions));
            }
            b'C' => {
                let (&kind, rest) = payload
                    .split_first()
                    .ok_or(LedgerError::Protocol("empty Close"))?;
                let (name, trailing) = cstring(rest)?;
                if !trailing.is_empty() {
                    return Err(LedgerError::Protocol("invalid Close"));
                }
                self.pending.push_back(match kind {
                    b'S' => Pending::CloseStatement(name),
                    b'P' => Pending::ClosePortal(name),
                    _ => return Err(LedgerError::Protocol("invalid Close target")),
                });
            }
            b'S' => self.pending.push_back(Pending::Sync),
            _ => {}
        }
        self.check_budget()
    }
    /// Preserve the native command tag when RESET is adapted for backend transport.
    /// Call before `backend`, which consumes the original pending action.
    pub fn rewrite_backend(&self, tag: u8, payload: &[u8]) -> Option<Vec<u8>> {
        if tag != b'C' {
            return None;
        }
        let action = match self.pending.front()? {
            Pending::Query(actions) | Pending::Execute(actions) => actions.front()?,
            _ => return None,
        };
        match action {
            Action::ResetAll if payload == b"DO\0" && !self.startup_defaults.is_empty() => {
                Some(b"RESET\0".to_vec())
            }
            Action::Reset(name, true)
                if payload == b"SET\0"
                    && self.startup_defaults.iter().any(|(key, _)| key == name) =>
            {
                Some(b"RESET\0".to_vec())
            }
            _ => None,
        }
    }
    pub fn backend(&mut self, tag: u8, payload: &[u8]) -> Result<(), LedgerError> {
        match tag {
            b'1' => {
                if let Some(Pending::Parse(mut p)) = self.pending.pop_front() {
                    p.context = self.state.settings.clone();
                    if self.state.local_affects_parse {
                        self.state.opaque = true;
                    }
                    self.prepared.insert(p.name.clone(), p);
                }
            }
            b'2' => {
                if let Some(Pending::Bind(portal, statement)) = self.pending.pop_front() {
                    self.portals.insert(portal, statement);
                }
            }
            b'3' => match self.pending.pop_front() {
                Some(Pending::CloseStatement(name)) => {
                    self.prepared.remove(&name);
                    self.sql_prepared.remove(&name);
                }
                Some(Pending::ClosePortal(name)) => {
                    self.portals.remove(&name);
                }
                _ => {}
            },
            b'C' => {
                let command = std::str::from_utf8(payload).unwrap_or("");
                let action = match self.pending.front_mut() {
                    Some(Pending::Execute(actions)) | Some(Pending::Query(actions)) => {
                        actions.pop_front()
                    }
                    _ => None,
                };
                if let Some(action) = action {
                    self.apply(action, command);
                }
                if matches!(self.pending.front(), Some(Pending::Execute(actions)) if actions.is_empty())
                {
                    self.pending.pop_front();
                }
                // A confirmed unlock/reset cannot revoke protection for a later
                // already-forwarded action in this batch that may fail after effects.
                let remaining = self
                    .pending
                    .iter()
                    .filter_map(|pending| match pending {
                        Pending::Query(actions) | Pending::Execute(actions) => Some(actions.iter()),
                        _ => None,
                    })
                    .flatten()
                    .cloned()
                    .collect();
                self.guard_nontransactional_effects(&remaining);
            }
            b's' => {
                if matches!(self.pending.front(), Some(Pending::Execute(_))) {
                    self.pending.pop_front();
                }
            }
            b'I' => {
                if matches!(self.pending.front(), Some(Pending::Execute(_))) {
                    self.pending.pop_front();
                }
            }
            b'E' => {
                self.error = true;
                if let Some(checkpoint) = &self.checkpoint {
                    self.state = checkpoint.clone();
                }
                while !matches!(
                    self.pending.front(),
                    None | Some(Pending::Sync) | Some(Pending::Query(_))
                ) {
                    self.pending.pop_front();
                }
                if let Some(Pending::Query(actions)) = self.pending.front_mut() {
                    actions.clear();
                }
            }
            b'Z' => {
                if matches!(
                    self.pending.front(),
                    Some(Pending::Sync) | Some(Pending::Query(_))
                ) {
                    self.pending.pop_front();
                }
                if payload == b"I" {
                    if self.error
                        && let Some(checkpoint) = self.checkpoint.take()
                    {
                        self.state = checkpoint;
                    }
                    self.checkpoint = None;
                    self.savepoints.clear();
                    self.state.local = false;
                    self.state.local_affects_parse = false;
                    self.state.parser_options = self.state.persistent_parser_options;
                    self.state.cursors.retain(|_, hold| *hold);
                    self.eligible_cursors
                        .retain(|name| self.state.cursors.contains_key(name));
                    self.portals.clear();
                }
                self.error = false;
            }
            _ => {}
        }
        self.check_budget()
    }
    fn apply(&mut self, action: Action, command: &str) {
        match action {
            Action::Set(name, sql) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                upsert(&mut self.state.settings, name.clone(), sql);
                if name == "standard_conforming_strings" || name == "backslash_quote" {
                    self.state.opaque = true;
                }
            }
            Action::LocalParserSet(name, value) => {
                self.state.local = true;
                self.state.local_affects_parse = true;
                if let Some(value) = value {
                    match name.as_str() {
                        "standard_conforming_strings" => {
                            self.state.parser_options.standard_conforming_strings = value
                        }
                        "backslash_quote" => self.state.parser_options.backslash_quote = value,
                        _ => {}
                    }
                }
            }
            Action::Reset(name, _) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                match name.as_str() {
                    "standard_conforming_strings" => {
                        self.state.parser_options.standard_conforming_strings =
                            self.options.standard_conforming_strings;
                        self.state
                            .persistent_parser_options
                            .standard_conforming_strings = self.options.standard_conforming_strings
                    }
                    "backslash_quote" => {
                        self.state.parser_options.backslash_quote = self.options.backslash_quote;
                        self.state.persistent_parser_options.backslash_quote =
                            self.options.backslash_quote
                    }
                    _ => {}
                }
                self.state.settings.retain(|(key, _)| key != &name);
                if let Some((_, sql)) = self.startup_defaults.iter().find(|(key, _)| key == &name) {
                    upsert(&mut self.state.settings, name, sql.clone());
                }
            }
            Action::ParserSet(name, sql, value) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                upsert(&mut self.state.settings, name.clone(), sql);
                if let Some(value) = value {
                    match name.as_str() {
                        "standard_conforming_strings" => {
                            self.state.parser_options.standard_conforming_strings = value;
                            self.state
                                .persistent_parser_options
                                .standard_conforming_strings = value
                        }
                        "backslash_quote" => {
                            self.state.parser_options.backslash_quote = value;
                            self.state.persistent_parser_options.backslash_quote = value;
                        }
                        _ => {}
                    }
                }
                self.state.opaque = true;
            }
            Action::ResetAll => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                let role = self
                    .state
                    .settings
                    .iter()
                    .find(|(name, _)| name == "role")
                    .cloned();
                self.state.settings = self
                    .startup_defaults
                    .iter()
                    .filter(|(name, _)| name != "role")
                    .cloned()
                    .collect();
                if let Some((name, sql)) = role {
                    upsert(&mut self.state.settings, name, sql);
                }
                self.state.parser_options = self.options;
                self.state.persistent_parser_options = self.options;
            }
            Action::Begin => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
            }
            Action::Rollback => {
                if let Some(checkpoint) = self.checkpoint.take() {
                    self.state = checkpoint;
                }
                self.savepoints.clear();
            }
            Action::Commit => {
                if command.starts_with("ROLLBACK") {
                    if let Some(checkpoint) = self.checkpoint.take() {
                        self.state = checkpoint;
                    }
                } else {
                    self.checkpoint = None;
                }
                self.savepoints.clear();
                self.state.local = false;
                self.state.cursors.retain(|_, hold| *hold);
            }
            Action::Savepoint(name) => self.savepoints.push((name, self.state.clone())),
            Action::RollbackTo(name) => {
                if let Some(index) = self.savepoints.iter().rposition(|(n, _)| n == &name) {
                    self.state = self.savepoints[index].1.clone();
                    self.savepoints.truncate(index + 1);
                }
            }
            Action::Release(name) => {
                if let Some(index) = self.savepoints.iter().rposition(|(n, _)| n == &name) {
                    self.savepoints.truncate(index);
                }
            }
            Action::ExecuteSql(name) => {
                if let Some(prepared) = self.sql_prepared.get(&name)
                    && let Ok(parsed) = self.cache.parse(&prepared.sql, self.options)
                    && let Some(query) = parsed
                        .statements()
                        .next()
                        .and_then(|stmt| stmt.get("PrepareStmt"))
                        .and_then(|p| p.get("query"))
                {
                    let effect = classify(query, "", &self.state.settings);
                    self.apply(effect, command);
                }
            }
            Action::PrepareSql(mut p) => {
                p.context = self.state.settings.clone();
                if self.state.local_affects_parse {
                    self.state.opaque = true;
                }
                self.sql_prepared.insert(p.name.clone(), p);
            }
            Action::Deallocate(Some(name)) => {
                self.sql_prepared.remove(&name);
                self.prepared.remove(&name);
            }
            Action::Deallocate(None) => {
                self.prepared.clear();
                self.sql_prepared.clear();
            }
            Action::DiscardAll => {
                self.cursor_protocol = Default::default();
                self.virtual_cursors.clear();
                self.eligible_cursors.clear();
                self.pending_startup_restore = !self.startup_defaults.is_empty();
                self.uncertain_affinity = false;
                self.state = State {
                    settings: self.startup_defaults.clone(),
                    parser_options: self.options,
                    persistent_parser_options: self.options,
                    ..State::default()
                };
                self.state.opaque = self.startup_defaults.iter().any(|(name, _)| {
                    matches!(
                        name.as_str(),
                        "standard_conforming_strings" | "backslash_quote" | "client_encoding"
                    )
                });
                self.prepared.clear();
                self.sql_prepared.clear();
                self.portals.clear();
                self.checkpoint = None;
                self.advisory = false;
            }
            Action::Listen(name) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                self.state.listeners.insert(name);
            }
            Action::Unlisten(Some(name)) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                self.state.listeners.remove(&name);
            }
            Action::Unlisten(None) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                self.state.listeners.clear();
            }
            Action::Cursor(name, hold, eligible) => {
                if eligible {
                    self.eligible_cursors.insert(name.clone());
                } else {
                    self.eligible_cursors.remove(&name);
                }
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                self.state.cursors.insert(name, hold);
            }
            Action::TouchCursor(name) => {
                self.eligible_cursors.remove(&name);
            }
            Action::CloseCursor(Some(name)) => {
                self.virtual_cursors.remove(&name);
                self.eligible_cursors.remove(&name);
                self.state.cursors.remove(&name);
            }
            Action::CloseCursor(None) => {
                self.state.cursors.clear();
                self.virtual_cursors.clear();
                self.eligible_cursors.clear();
            }
            Action::Temp(name) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                self.state.temps.insert(name);
            }
            Action::DropTemp(names) => {
                self.checkpoint.get_or_insert_with(|| self.state.clone());
                for name in names {
                    self.state.temps.remove(&name);
                }
            }
            Action::Pin => self.state.opaque = true,
            Action::Local(name) => {
                self.state.local = true;
                // These settings cannot alter interpretation of a prepared SQL
                // text. Other local GUCs retain conservative parse-context affinity.
                if !matches!(
                    name.as_str(),
                    "application_name"
                        | "statement_timeout"
                        | "lock_timeout"
                        | "idle_in_transaction_session_timeout"
                        | "idle_session_timeout"
                ) {
                    self.state.local_affects_parse = true;
                }
            }
            Action::Advisory => self.advisory = true,
            Action::UnlockAll => self.advisory = false,
            Action::None => {}
        }
    }
}
fn boolean_set_literal(sql: &str) -> Option<bool> {
    let lower = sql.to_ascii_lowercase();
    lower
        .split(['=', ' '])
        .filter(|part| !part.is_empty())
        .next_back()
        .and_then(|part| guc_boolean(part.trim_matches(['\'', ';'])))
}
fn guc_boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}
fn action_charge(action: &Action) -> usize {
    256 + match action {
        Action::Set(name, sql) | Action::ParserSet(name, sql, _) => name.len() + sql.len(),
        Action::Reset(name, _) | Action::LocalParserSet(name, _) | Action::Local(name) => {
            name.len()
        }
        Action::PrepareSql(p) => {
            p.name.len()
                + p.sql.len()
                + p.context
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 128)
                    .sum::<usize>()
        }
        Action::Savepoint(name)
        | Action::RollbackTo(name)
        | Action::Release(name)
        | Action::ExecuteSql(name)
        | Action::Listen(name)
        | Action::Temp(name) => name.len(),
        Action::Deallocate(name) | Action::Unlisten(name) | Action::CloseCursor(name) => {
            name.as_ref().map_or(0, String::len)
        }
        Action::Cursor(name, _, _) | Action::TouchCursor(name) => name.len(),
        Action::DropTemp(names) => names.iter().map(|name| name.len() + 32).sum(),
        _ => 0,
    }
}
fn upsert(settings: &mut Settings, name: String, sql: String) {
    settings.retain(|(key, _)| key != &name);
    settings.push((name, sql));
}
fn cstring(bytes: &[u8]) -> Result<(String, &[u8]), LedgerError> {
    let index = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(LedgerError::Protocol("missing terminator"))?;
    let text = std::str::from_utf8(&bytes[..index])
        .map_err(|_| LedgerError::Protocol("non-UTF8 SQL or identifier"))?;
    Ok((text.into(), &bytes[index + 1..]))
}
fn string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}
fn classify(stmt: &Value, sql: &str, context: &Settings) -> Action {
    if let Some(set) = stmt.get("VariableSetStmt") {
        let name = string(set, "name");
        if set.get("is_local").and_then(Value::as_bool) == Some(true) {
            if matches!(
                name.as_str(),
                "standard_conforming_strings" | "backslash_quote"
            ) {
                return Action::LocalParserSet(name, boolean_set_literal(sql));
            }
            return Action::Local(name);
        }
        if matches!(name.as_str(), "session_authorization" | "client_encoding") {
            return Action::Pin;
        }
        return match string(set, "kind").as_str() {
            "VAR_RESET_ALL" => Action::ResetAll,
            "VAR_SET_DEFAULT" => Action::Reset(name, false),
            "VAR_RESET" => Action::Reset(name, true),
            "VAR_SET_VALUE"
                if matches!(
                    name.as_str(),
                    "standard_conforming_strings" | "backslash_quote"
                ) =>
            {
                // These settings change parsing itself. Keep physical affinity and
                // update the cache key only for an unambiguous literal value.
                let value = boolean_set_literal(sql);
                Action::ParserSet(name, sql.into(), value)
            }
            "VAR_SET_VALUE" => Action::Set(name, sql.into()),
            _ => Action::Pin,
        };
    }
    if let Some(tx) = stmt.get("TransactionStmt") {
        return match string(tx, "kind").as_str() {
            "TRANS_STMT_BEGIN" | "TRANS_STMT_START" => Action::Begin,
            "TRANS_STMT_COMMIT" => Action::Commit,
            "TRANS_STMT_ROLLBACK" => Action::Rollback,
            "TRANS_STMT_SAVEPOINT" => Action::Savepoint(string(tx, "savepoint_name")),
            "TRANS_STMT_ROLLBACK_TO" => Action::RollbackTo(string(tx, "savepoint_name")),
            "TRANS_STMT_RELEASE" => Action::Release(string(tx, "savepoint_name")),
            _ => Action::Pin,
        };
    }
    if let Some(p) = stmt.get("PrepareStmt") {
        return Action::PrepareSql(Prepared {
            name: string(p, "name"),
            sql: sql.into(),
            payload: None,
            context: context.clone(),
        });
    }
    if let Some(e) = stmt.get("ExecuteStmt") {
        return Action::ExecuteSql(string(e, "name"));
    }
    if let Some(d) = stmt.get("DeallocateStmt") {
        return Action::Deallocate(d.get("name").and_then(Value::as_str).map(str::to_owned));
    }
    if let Some(d) = stmt.get("DiscardStmt") {
        return if string(d, "target") == "DISCARD_ALL" {
            Action::DiscardAll
        } else {
            Action::None
        };
    }
    if let Some(l) = stmt.get("ListenStmt") {
        return Action::Listen(string(l, "conditionname"));
    }
    if let Some(l) = stmt.get("UnlistenStmt") {
        return Action::Unlisten(
            l.get("conditionname")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
    }
    if let Some(c) = stmt.get("DeclareCursorStmt") {
        let flags = c.get("options").and_then(Value::as_u64).unwrap_or(0);
        let safe = c
            .get("query")
            .is_some_and(|q| matches!(classify(q, sql, context), Action::None));
        if !safe {
            return Action::Pin;
        }
        return Action::Cursor(string(c, "portalname"), flags & 32 != 0, flags & 35 == 34);
    }
    if let Some(c) = stmt.get("FetchStmt") {
        return Action::TouchCursor(string(c, "portalname"));
    }
    if let Some(c) = stmt.get("ClosePortalStmt") {
        return Action::CloseCursor(
            c.get("portalname")
                .and_then(Value::as_str)
                .map(str::to_owned),
        );
    }
    if let Some(c) = stmt.get("CreateStmt")
        && let Some(relation) = c.get("relation")
        && string(relation, "relpersistence") == "t"
    {
        return Action::Temp(string(relation, "relname"));
    }
    if let Some(d) = stmt.get("DropStmt")
        && string(d, "removeType") == "OBJECT_TABLE"
    {
        let names = d
            .get("objects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|o| {
                let items = o.get("List")?.get("items")?.as_array()?;
                if items.len() == 1 && context.iter().any(|(name, _)| name == "search_path") {
                    return None;
                }
                if items.len() > 1 {
                    let schema = items.first()?.get("String")?.get("sval")?.as_str()?;
                    if schema != "pg_temp" && !schema.starts_with("pg_temp_") {
                        return None;
                    }
                }
                items.last()?.get("String")?.get("sval")?.as_str()
            })
            .map(str::to_owned)
            .collect();
        return Action::DropTemp(names);
    }
    let mut functions = Vec::new();
    collect_functions(stmt, &mut functions);
    let pure = |function: &str| {
        let base = function.strip_prefix("pg_catalog.").unwrap_or(function);
        let known = matches!(
            base,
            "count"
                | "sum"
                | "min"
                | "max"
                | "avg"
                | "generate_series"
                | "pg_advisory_xact_lock"
                | "pg_try_advisory_xact_lock"
                | "pg_advisory_unlock"
                | "pg_advisory_unlock_shared"
                | "pg_advisory_lock"
                | "pg_advisory_lock_shared"
                | "pg_try_advisory_lock"
                | "pg_try_advisory_lock_shared"
                | "pg_advisory_unlock_all"
                | "now"
                | "current_setting"
                | "pg_backend_pid"
                | "pg_sleep"
                | "pg_notify"
        );
        known
            && (function.starts_with("pg_catalog.")
                || (!function.contains('.')
                    && !context.iter().any(|(name, _)| name == "search_path")))
    };
    if functions.iter().any(|function| !pure(function)) {
        return Action::Pin;
    }
    if functions.iter().any(|function| {
        matches!(
            function.strip_prefix("pg_catalog.").unwrap_or(function),
            "pg_advisory_lock"
                | "pg_advisory_lock_shared"
                | "pg_try_advisory_lock"
                | "pg_try_advisory_lock_shared"
        )
    }) {
        return Action::Advisory;
    }
    if functions.iter().any(|function| {
        function.strip_prefix("pg_catalog.").unwrap_or(function) == "pg_advisory_unlock_all"
    }) {
        return Action::UnlockAll;
    }
    if stmt.as_object().is_some_and(|o| {
        o.keys().any(|k| {
            matches!(
                k.as_str(),
                "VariableShowStmt"
                    | "SelectStmt"
                    | "InsertStmt"
                    | "UpdateStmt"
                    | "DeleteStmt"
                    | "MergeStmt"
                    | "CopyStmt"
                    | "NotifyStmt"
                    | "ExecuteStmt"
                    | "FetchStmt"
                    | "CreateStmt"
                    | "AlterTableStmt"
                    | "DropStmt"
                    | "IndexStmt"
                    | "TruncateStmt"
            )
        })
    }) {
        Action::None
    } else {
        Action::Pin
    }
}
fn collect_functions(value: &Value, out: &mut Vec<String>) {
    if let Some(names) = value
        .get("FuncCall")
        .and_then(|f| f.get("funcname"))
        .and_then(Value::as_array)
    {
        let parts: Vec<_> = names
            .iter()
            .filter_map(|n| n.get("String")?.get("sval")?.as_str())
            .collect();
        out.push(parts.join("."));
    }

    match value {
        Value::Object(m) => {
            for v in m.values() {
                collect_functions(v, out)
            }
        }
        Value::Array(a) => {
            for v in a {
                collect_functions(v, out)
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ledger() -> SessionLedger {
        SessionLedger::new(1024 * 1024, 65536, Default::default())
    }
    fn query(l: &mut SessionLedger, sql: &str, commands: &[&str], status: u8) {
        let mut bytes = sql.as_bytes().to_vec();
        bytes.push(0);
        l.frontend(b'Q', &bytes).unwrap();
        for command in commands {
            let mut b = command.as_bytes().to_vec();
            b.push(0);
            l.backend(b'C', &b).unwrap();
        }
        l.backend(b'Z', &[status]).unwrap();
    }
    #[test]
    fn settings_commit_rollback_and_savepoints_follow_server_completions() {
        let mut l = ledger();
        query(&mut l, "SET application_name='base'", &["SET"], b'I');
        query(
            &mut l,
            "BEGIN; SET application_name='changed'; SAVEPOINT s; SET search_path=public; ROLLBACK TO s; ROLLBACK",
            &["BEGIN", "SET", "SAVEPOINT", "SET", "ROLLBACK", "ROLLBACK"],
            b'I',
        );
        let replay = l.restore();
        assert!(format!("{replay:?}").contains("base"));
        assert!(!format!("{replay:?}").contains("changed"));
        assert!(!format!("{replay:?}").contains("search_path"));
        query(
            &mut l,
            "BEGIN; SET application_name='committed'; COMMIT",
            &["BEGIN", "SET", "COMMIT"],
            b'I',
        );
        assert!(format!("{:?}", l.restore()).contains("committed"));
    }
    #[test]
    fn stateful_server_objects_pin_until_explicitly_removed() {
        let mut l = ledger();
        query(&mut l, "LISTEN test", &["LISTEN"], b'I');
        assert!(l.is_pinned());
        query(&mut l, "UNLISTEN *", &["UNLISTEN"], b'I');
        assert!(!l.is_pinned());
        query(
            &mut l,
            "BEGIN; DECLARE c CURSOR WITH HOLD FOR SELECT 1; COMMIT",
            &["BEGIN", "DECLARE CURSOR", "COMMIT"],
            b'I',
        );
        assert!(l.is_pinned());
        query(&mut l, "CLOSE c", &["CLOSE CURSOR"], b'I');
        assert!(!l.is_pinned());
        query(
            &mut l,
            "CREATE TEMP TABLE t(a int)",
            &["CREATE TABLE"],
            b'I',
        );
        assert!(l.is_pinned());
        query(&mut l, "DROP TABLE t", &["DROP TABLE"], b'I');
        assert!(!l.is_pinned());
    }
    #[test]
    fn failed_parse_is_not_committed_and_simple_query_destroys_unnamed() {
        let mut l = ledger();
        l.frontend(b'P', b"p\0SELECT 1\0\0\0").unwrap();
        assert!(l.restore().is_empty());
        l.backend(b'1', &[]).unwrap();
        assert!(matches!(l.restore()[0], RestoreCommand::Parse(_)));
        l.frontend(b'P', b"bad\0SELECT FROM\0\0\0").unwrap();
        l.frontend(b'S', &[]).unwrap();
        l.backend(b'E', &[]).unwrap();
        l.backend(b'Z', b"I").unwrap();
        assert_eq!(l.prepared.len(), 1);
        l.frontend(b'P', b"\0SELECT 2\0\0\0").unwrap();
        l.backend(b'1', &[]).unwrap();
        l.frontend(b'S', &[]).unwrap();
        l.backend(b'Z', b"I").unwrap();
        query(&mut l, "SELECT 3", &["SELECT 1"], b'I');
        assert!(!l.prepared.contains_key(""));
    }
    #[test]
    fn implicit_multi_statement_error_rolls_back_settings() {
        let mut l = ledger();
        let mut q = b"SET application_name='bad'; SELECT 1/0".to_vec();
        q.push(0);
        l.frontend(b'Q', &q).unwrap();
        l.backend(b'C', b"SET\0").unwrap();
        l.backend(b'E', &[]).unwrap();
        l.backend(b'Z', b"I").unwrap();
        assert!(l.restore().is_empty());
    }
    #[test]
    fn sql_prepare_and_deallocate_are_confirmed() {
        let mut l = ledger();
        query(&mut l, "PREPARE p AS SELECT 1", &["PREPARE"], b'I');
        assert!(format!("{:?}", l.restore()).contains("PREPARE"));
        query(&mut l, "DEALLOCATE p", &["DEALLOCATE"], b'I');
        assert!(l.restore().is_empty());
    }
    #[test]
    fn unknown_functions_pin_and_budget_is_enforced() {
        let mut l = ledger();
        query(&mut l, "SELECT extension_state()", &["SELECT 1"], b'I');
        assert!(l.is_pinned());
        let mut tiny = SessionLedger::new(10, 65536, Default::default());
        assert!(
            tiny.startup_setting("application_name", "long-value")
                .is_err()
        );
    }
    #[test]
    fn reset_preserves_startup_defaults_and_transaction_rollback() {
        let mut l = ledger();
        l.startup_setting("application_name", "startup").unwrap();
        query(&mut l, "SET application_name='changed'", &["SET"], b'I');
        query(&mut l, "RESET application_name", &["RESET"], b'I');
        assert!(format!("{:?}", l.restore()).contains("startup"));
        query(&mut l, "SET application_name='changed'", &["SET"], b'I');
        query(
            &mut l,
            "BEGIN; RESET ALL; ROLLBACK",
            &["BEGIN", "RESET", "ROLLBACK"],
            b'I',
        );
        assert!(format!("{:?}", l.restore()).contains("changed"));
        query(&mut l, "RESET ALL", &["DO"], b'I');
        assert!(!format!("{:?}", l.restore()).contains("changed"));
        assert!(format!("{:?}", l.restore()).contains("startup"));
    }
    #[test]
    fn rewritten_resets_preserve_statement_boundaries_and_quoted_values() {
        let mut l = ledger();
        l.startup_setting(
            "application_name",
            "x'; SELECT danger(); -- $pgproxy_reset$",
        )
        .unwrap();
        let rewritten = l
            .rewrite_query("SELECT 1; RESET application_name; SELECT 2")
            .unwrap()
            .unwrap();
        assert!(rewritten.starts_with("SELECT 1; SET"), "{rewritten}");
        assert!(rewritten.ends_with("; SELECT 2"));
        assert!(rewritten.contains("x\\';"));
        let all = l.rewrite_query("RESET ALL").unwrap().unwrap();
        assert!(all.starts_with("DO $pgproxy_reset_$"));
        assert!(l.cache.parse(&all, l.options).is_ok());
        assert!(
            l.rewrite_query("RESET LOCAL application_name")
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn parse_replay_stores_rewritten_transport_and_original_intent() {
        let mut l = ledger();
        l.startup_setting("application_name", "startup").unwrap();
        let payload = b"resetter\0RESET ALL\0\0\0";
        l.frontend(b'P', payload).unwrap();
        l.backend(b'1', &[]).unwrap();
        let p = &l.prepared["resetter"];
        assert_eq!(p.sql, "RESET ALL");
        assert!(p.payload.as_ref().unwrap().windows(3).any(|b| b == b"DO "));
    }
    #[test]
    fn discard_retains_startup_image_and_affinity_policy() {
        let mut l = ledger();
        l.startup_setting("standard_conforming_strings", "off")
            .unwrap();
        l.retain_backend_for_session();
        query(&mut l, "DISCARD ALL", &["DISCARD ALL"], b'I');
        assert!(l.is_pinned());
        assert!(!l.state.parser_options.standard_conforming_strings);
        assert_eq!(l.startup_restore().len(), 1);
        assert_eq!(l.take_startup_restore().len(), 1);
        assert!(l.take_startup_restore().is_empty());
        assert!(l.pin_reasons().contains(&"session pooling"));
    }
    #[test]
    fn parser_context_rolls_back_and_reset_uses_startup_context() {
        let mut l = ledger();
        query(
            &mut l,
            "BEGIN; SET standard_conforming_strings=off",
            &["BEGIN", "SET"],
            b'T',
        );
        assert!(!l.state.parser_options.standard_conforming_strings);
        query(&mut l, "ROLLBACK", &["ROLLBACK"], b'I');
        assert!(l.state.parser_options.standard_conforming_strings);
        l.startup_setting("standard_conforming_strings", "off")
            .unwrap();
        query(&mut l, "SET standard_conforming_strings=on", &["SET"], b'I');
        assert!(l.state.parser_options.standard_conforming_strings);
        query(&mut l, "RESET standard_conforming_strings", &["SET"], b'I');
        assert!(!l.state.parser_options.standard_conforming_strings);
    }
    #[test]
    fn dropping_same_named_permanent_table_keeps_temp_affinity() {
        let mut l = ledger();
        query(
            &mut l,
            "CREATE TEMP TABLE collision(a int)",
            &["CREATE TABLE"],
            b'I',
        );
        query(&mut l, "DROP TABLE public.collision", &["DROP TABLE"], b'I');
        assert!(l.is_pinned());
        query(
            &mut l,
            "DROP TABLE pg_temp.collision",
            &["DROP TABLE"],
            b'I',
        );
        assert!(!l.is_pinned());
    }
    #[test]
    fn prepared_statement_survives_transaction_rollback_as_postgres_does() {
        let mut l = ledger();
        query(
            &mut l,
            "BEGIN; PREPARE p AS SELECT 42; ROLLBACK",
            &["BEGIN", "PREPARE", "ROLLBACK"],
            b'I',
        );
        assert!(l.sql_prepared.contains_key("p"));
    }
    #[test]
    fn ddl_on_affinity_backend_preserves_prepared_ownership() {
        let mut l = ledger();
        query(
            &mut l,
            "LISTEN retain_me; PREPARE p AS SELECT 42",
            &["LISTEN", "PREPARE"],
            b'I',
        );
        query(
            &mut l,
            "ALTER TABLE migration_probe ADD COLUMN b bigint",
            &["ALTER TABLE"],
            b'I',
        );
        assert!(l.is_pinned());
        assert!(l.sql_prepared.contains_key("p"));
    }
    #[test]
    fn session_function_effects_retain_ownership_even_when_query_errors() {
        for sql in [
            "SELECT pg_catalog.pg_advisory_lock(42), 1/0",
            "SELECT extension_mutates_state(), 1/0",
        ] {
            let mut l = ledger();
            let mut payload = sql.as_bytes().to_vec();
            payload.push(0);
            l.frontend(b'Q', &payload).unwrap();
            assert!(l.is_pinned());
            l.backend(b'E', &[]).unwrap();
            l.backend(b'Z', b"I").unwrap();
            assert!(l.is_pinned());
            query(&mut l, "DISCARD ALL", &["DISCARD ALL"], b'I');
            assert!(!l.is_pinned());
        }
    }
    #[test]
    fn sql_execute_function_guard_is_applied_before_completion() {
        let mut l = ledger();
        query(
            &mut l,
            "PREPARE locking AS SELECT pg_catalog.pg_advisory_lock(42), 1/0",
            &["PREPARE"],
            b'I',
        );
        assert!(!l.is_pinned());
        l.frontend(b'Q', b"EXECUTE locking\0").unwrap();
        assert!(l.is_pinned());
        l.backend(b'E', &[]).unwrap();
        l.backend(b'Z', b"I").unwrap();
        assert!(l.is_pinned());
        query(
            &mut l,
            "SELECT pg_catalog.pg_advisory_unlock_all()",
            &["SELECT 1"],
            b'I',
        );
        assert!(!l.is_pinned());
    }
    #[test]
    fn discard_barrier_allows_extended_sync_then_waits_for_replay() {
        let mut l = ledger();
        l.startup_setting("application_name", "startup").unwrap();
        l.frontend(b'P', b"d\0DISCARD ALL\0\0\0").unwrap();
        l.backend(b'1', &[]).unwrap();
        l.frontend(b'B', b"\0d\0").unwrap();
        l.backend(b'2', &[]).unwrap();
        l.frontend(b'E', b"\0\0\0\0\0").unwrap();
        assert!(l.awaiting_discard_sync());
        assert!(!l.frontend_barrier());
        l.frontend(b'S', &[]).unwrap();
        assert!(l.frontend_barrier());
        l.backend(b'C', b"DISCARD ALL\0").unwrap();
        l.backend(b'Z', b"I").unwrap();
        // The caller drains replay immediately at RFQ before another frontend poll.
        assert_eq!(l.take_startup_restore().len(), 1);
        assert!(!l.frontend_barrier());
    }
    #[test]
    fn discard_completion_before_sync_must_still_allow_sync() {
        let mut l = ledger();
        l.startup_setting("application_name", "startup").unwrap();
        l.frontend(b'P', b"d\0DISCARD ALL\0\0\0").unwrap();
        l.backend(b'1', &[]).unwrap();
        l.frontend(b'B', b"\0d\0").unwrap();
        l.backend(b'2', &[]).unwrap();
        l.frontend(b'E', b"\0\0\0\0\0").unwrap();
        l.backend(b'C', b"DISCARD ALL\0").unwrap();
        assert!(!l.frontend_barrier());
        assert!(l.awaiting_discard_sync());
        l.frontend(b'S', &[]).unwrap();
        assert!(l.frontend_barrier());
    }
    #[test]
    fn earlier_unlock_cannot_clear_guard_for_later_failing_lock() {
        let mut l = ledger();
        l.frontend(b'Q', b"SELECT pg_catalog.pg_advisory_unlock_all(); SELECT pg_catalog.pg_advisory_lock(42), 1/0\0").unwrap();
        l.backend(b'C', b"SELECT 1\0").unwrap();
        assert!(l.is_pinned());
        l.backend(b'E', &[]).unwrap();
        l.backend(b'Z', b"I").unwrap();
        assert!(l.is_pinned());
    }
    #[test]
    fn show_is_stateless_and_does_not_pin_the_pool() {
        let mut l = ledger();
        query(&mut l, "SHOW application_name", &["SHOW"], b'I');
        assert!(!l.is_pinned());
    }
    #[test]
    fn local_parser_settings_expire_at_transaction_end() {
        let mut l = ledger();
        query(
            &mut l,
            "BEGIN; SET LOCAL standard_conforming_strings=off",
            &["BEGIN", "SET"],
            b'T',
        );
        assert!(!l.state.parser_options.standard_conforming_strings);
        assert!(
            l.state
                .persistent_parser_options
                .standard_conforming_strings
        );
        query(&mut l, "COMMIT", &["COMMIT"], b'I');
        assert!(l.state.parser_options.standard_conforming_strings);
        query(
            &mut l,
            "SET LOCAL standard_conforming_strings=off",
            &["SET"],
            b'I',
        );
        assert!(l.state.parser_options.standard_conforming_strings);
    }
    #[test]
    fn rewritten_reset_returns_original_native_command_tag() {
        let mut l = ledger();
        l.startup_setting("application_name", "startup").unwrap();
        l.frontend(b'Q', b"RESET application_name\0").unwrap();
        assert_eq!(l.rewrite_backend(b'C', b"SET\0"), Some(b"RESET\0".to_vec()));
        l.backend(b'C', b"SET\0").unwrap();
        l.backend(b'Z', b"I").unwrap();
        l.frontend(b'Q', b"SET application_name TO DEFAULT\0")
            .unwrap();
        assert!(l.rewrite_backend(b'C', b"SET\0").is_none());
        l.backend(b'C', b"SET\0").unwrap();
        l.backend(b'Z', b"I").unwrap();
        l.frontend(b'Q', b"RESET ALL\0").unwrap();
        assert_eq!(l.rewrite_backend(b'C', b"DO\0"), Some(b"RESET\0".to_vec()));
        assert!(l.rewrite_backend(b'E', b"DO\0").is_none());
    }
    #[test]
    fn backend_major_is_negotiated_before_sql_and_cannot_change_mid_session() {
        let mut l = ledger();
        l.set_backend_major(14).unwrap();
        assert_eq!(l.options.backend_major, 14);
        assert_eq!(l.state.parser_options.backend_major, 14);
        query(&mut l, "SELECT 1", &["SELECT 1"], b'I');
        assert!(l.set_backend_major(18).is_err());
        assert!(ledger().set_backend_major(13).is_err());
    }
    #[test]
    fn prepare_under_local_application_name_does_not_retain_backend() {
        let mut l = ledger();
        query(
            &mut l,
            "BEGIN; SET LOCAL application_name='driver-local'",
            &["BEGIN", "SET"],
            b'T',
        );
        l.frontend(b'P', b"show_name\0SHOW application_name\0\0\0")
            .unwrap();
        l.backend(b'1', &[]).unwrap();
        l.frontend(b'S', &[]).unwrap();
        l.backend(b'Z', b"T").unwrap();
        query(&mut l, "COMMIT", &["COMMIT"], b'I');
        assert!(!l.is_pinned());
        assert!(l.prepared.contains_key("show_name"));
    }
    #[test]
    fn prepare_under_local_search_path_retains_conservative_affinity() {
        let mut l = ledger();
        query(
            &mut l,
            "BEGIN; SET LOCAL search_path=public",
            &["BEGIN", "SET"],
            b'T',
        );
        l.frontend(b'P', b"scoped\0SELECT 1\0\0\0").unwrap();
        l.backend(b'1', &[]).unwrap();
        l.frontend(b'S', &[]).unwrap();
        l.backend(b'Z', b"T").unwrap();
        query(&mut l, "COMMIT", &["COMMIT"], b'I');
        assert!(l.is_pinned());
    }
    #[test]
    fn persistent_role_is_replayable_and_reset_all_preserves_it() {
        let mut l = ledger();
        query(&mut l, "SET ROLE tenant_reader", &["SET"], b'I');
        assert!(!l.is_pinned());
        assert!(format!("{:?}", l.restore()).contains("SET ROLE tenant_reader"));
        query(&mut l, "RESET ALL", &["RESET"], b'I');
        assert!(format!("{:?}", l.restore()).contains("SET ROLE tenant_reader"));
        query(&mut l, "RESET ROLE", &["RESET"], b'I');
        assert!(!format!("{:?}", l.restore()).contains("tenant_reader"));
    }
    #[test]
    fn preparation_role_context_resets_role_before_each_context_change() {
        let mut l = ledger();
        query(
            &mut l,
            "PREPARE before_role AS SELECT 1",
            &["PREPARE"],
            b'I',
        );
        query(
            &mut l,
            "SET ROLE tenant_reader; PREPARE after_role AS SELECT 2",
            &["SET", "PREPARE"],
            b'I',
        );
        let commands = l.restore();
        let queries = commands
            .iter()
            .filter_map(|command| match command {
                RestoreCommand::Query(sql) => Some(sql.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(
            queries
                .windows(2)
                .any(|pair| pair == ["RESET ROLE", "RESET ALL"])
        );
        let before = queries
            .iter()
            .position(|sql| sql.starts_with("PREPARE before_role"))
            .unwrap();
        assert!(queries[..before].contains(&"RESET ROLE"));
    }
    #[test]
    fn role_changes_roll_back_and_session_authorization_stays_affine() {
        let mut l = ledger();
        query(&mut l, "SET ROLE baseline", &["SET"], b'I');
        query(
            &mut l,
            "BEGIN; SET ROLE changed; ROLLBACK",
            &["BEGIN", "SET", "ROLLBACK"],
            b'I',
        );
        assert!(format!("{:?}", l.restore()).contains("baseline"));
        assert!(!format!("{:?}", l.restore()).contains("changed"));
        query(
            &mut l,
            "SET SESSION AUTHORIZATION other_user",
            &["SET"],
            b'I',
        );
        assert!(l.is_pinned());
    }
}
