# Documentation

Current documentation, reviewed 2026-09-30. Start with implementation status.
Each topic has one maintained page; previous versions are available in Git.

| Page | Purpose |
|---|---|
| [Implementation status](plans/implementation-status.md) | Implemented behavior, limitations and latest verification |
| [Architecture overview](architecture/overview.md) | Current components, threading, dependencies and data flow |
| [Remaining state virtualization](architecture/remaining-state-virtualization.md) | Cursor restrictions and temp/lock/notification migration requirements |
| [Roadmap](vision/roadmap.md) | Remaining work and acceptance criteria |
| [Product thesis](vision/product-thesis.md) | Audience, value proposition and product boundaries |
| [Architecture decisions](adr/README.md) | Current decisions and unresolved proposals |
| [Ledger testing](testing/ledger-semantics.md) | State replay and cursor semantics |
| [Operations and governance](testing/operations-and-governance.md) | HTTP operations, policy, fairness and MCP |
| [Reload and capacity](testing/reload-and-capacity.md) | Generations, draining and shared backend limits |
| [Credentials and usage](testing/credentials-and-usage.md) | Credential adapters and measurement semantics |
| [Latest verification evidence](../deliverables/verification-next/README.md) | Source-bound results and certification gaps |

Implemented mechanisms, compatibility fallbacks, planned features and verified
acceptance gates are distinct. Proposed decisions require approval; local test
results do not establish production certification.
