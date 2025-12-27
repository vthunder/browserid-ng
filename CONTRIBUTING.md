# Contributing to BrowserID-NG

## Testing Guidelines

### Always Run Full Test Suite After API Changes

When modifying any shared endpoint (e.g., `/wsapi/*`), run the **full** test suite, not just tests for the feature you're working on.

**Why?** API endpoints are often consumed by multiple parts of the codebase:
- `list_emails` is used by both `dialog.js` (email picker) and `user.js` (silent assertions)
- `session_context` is used by dialog, communication_iframe, and include.js

A change that fixes one consumer may break another.

```bash
# Don't just run one test file:
npx playwright test tests/silent-assertion.spec.ts  # ❌ Incomplete

# Run all tests:
npx playwright test                                   # ✅ Complete
```

### Setting Up the Pre-Push Hook

To automatically run all tests before pushing:

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-push
```

This will run both Rust unit tests and Playwright E2E tests before each push.

### Running Tests Manually

```bash
# Rust tests
cargo test

# E2E tests (from e2e-tests directory)
cd e2e-tests
npx playwright test

# Single E2E test file (for development iteration)
npx playwright test tests/sign-in.spec.ts
```

## Code Style

- Rust: Use `cargo fmt` and `cargo clippy`
- TypeScript/JavaScript: Follow existing patterns in the codebase
