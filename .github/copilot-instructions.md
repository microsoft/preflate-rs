# Repository guidance

Use the READMEs as the source of truth for architecture, APIs, commands, and
format details. Read the relevant guide before changing a component:

- [Project overview and developer workflow](../README.md)
- [Core DEFLATE analysis and reconstruction](../preflate/README.md)
- [CABAC codecs, tests, and benchmarks](../cabac/README.md)
- [Container processing and wire format](../container/README.md)
- [C ABI and DLL integration](../dll/README.md)
- [CLI](../util/README.md)
- [Integration tests and fixtures](../tests/README.md)
- [Standalone fuzz harnesses](../fuzz/README.md)

## Working conventions

- Preserve byte-exact reconstruction. Treat changes to prediction, corrections,
  or serialization as potential format compatibility changes; follow the
  versioning guidance in the project and DLL READMEs.
- Keep dependency requirements and workspace crate paths centralized in the root
  manifest. The fuzz package is intentionally standalone.
- Follow the safety restrictions and lint configuration already enforced by each
  crate. Do not introduce unsafe code outside the existing FFI boundary.
- Validate changes with the focused tests described in the developer workflow;
  use the integration tests when codec or container behavior changes.
- Keep documentation synchronized with code. Update the appropriate README
  rather than copying reference material into these instructions.
- Keep committed instructions and documentation applicable to all contributors:
  no machine-specific paths, personal preferences, or local environment settings.
