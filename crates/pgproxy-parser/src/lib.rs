//! libpg_query FFI, AST views, fingerprints, and the tiered parse decision.
//!
//! Status: scaffolding. See `docs/vision/roadmap.md` for the phase that implements this.
// `unsafe` is permitted in this crate only, per ADR-0001. Every block requires a
// written safety justification. See docs/adr/0001-language-and-runtime.md.
#![warn(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(test)]
mod tests {
    #[test]
    fn scaffolding_builds() {}
}
