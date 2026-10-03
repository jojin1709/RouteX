# Contributing to RouteX

Thank you for your interest in contributing to RouteX! We welcome bug fixes, documentation improvements, new stateless inspector tools, and edge optimizations.

## Core Architectural Principles

Before contributing code, please ensure your changes adhere to RouteX's three core tenets:

1. **100% Stateless**: No persistent storage, databases (D1, KV, R2), cookies, or user tracking.
2. **SSRF Defense-in-Depth**: All inbound destination URLs must be validated via `normalizeTarget()`.
3. **Cloudflare Free-Tier Native**: All features must run within standard serverless limits without requiring paid add-ons.

---

## Local Development Workflow

### Prerequisites
- [Node.js](https://nodejs.org/) v20+
- [Cloudflare Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Setup
```bash
# 1. Clone the repository
git clone https://github.com/jojin1709/RouteX.git
cd RouteX

# 2. Install dependencies
npm install

# 3. Start local edge development server
npm run dev
```

### Type Checking & Automated Testing
Before submitting any pull request, ensure all TypeScript checks and tests pass with zero errors:

```bash
# Run TypeScript compilation checks
npm run typecheck

# Run full automated test suite (166 tests)
npm test
```

---

## Submitting a Pull Request

1. Fork the repository and create your feature branch: `git checkout -b feat/my-new-tool`.
2. Commit your changes with clear, semantic commit messages: `git commit -m "feat(tools): add new ssl check"`.
3. Push to your branch: `git push origin feat/my-new-tool`.
4. Open a Pull Request on GitHub using our PR template.
