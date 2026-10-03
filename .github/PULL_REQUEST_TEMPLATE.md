## Description
Briefly describe the change, rationale, and problem it solves.

## Type of Change
- [ ] 🐛 Bug fix (non-breaking change fixing an issue)
- [ ] ✨ New feature (non-breaking change adding a new tool or endpoint)
- [ ] 🔒 Security hardening (SSRF, header sanitization, or input validation)
- [ ] 📝 Documentation update (README, OpenAPI, or code comments)
- [ ] ⚡ Performance optimization or refactor

## Architectural Constraints
- [ ] **100% Stateless**: Confirmed no state is persisted to persistent databases (D1, KV, R2).
- [ ] **SSRF Safe**: All target destinations pass through `normalizeTarget()` validation.
- [ ] **Cloudflare Free-Tier Native**: Operates within edge execution limits.

## Verification & Testing
- [ ] Ran `npm run typecheck` with 0 errors.
- [ ] Ran `npm test` and all automated test suites pass.
- [ ] Verified manually against local dev or edge environment.

### Test Results
```text
(Paste raw npm test summary here)
```
