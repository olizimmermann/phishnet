# Security Policy

## Supported Versions

Only the latest version on the `main` branch receives security fixes.

| Version | Supported |
|---------|-----------|
| latest (`main`) | Yes |
| older commits | No |

## Scope

This policy covers security vulnerabilities in the phishnet codebase itself — for example:

- Command injection, path traversal, or zip-slip in kit handling
- Credential or token leakage (config parsing, logging)
- Unsafe deserialization or file writes
- Dependency vulnerabilities with a direct exploitable impact

Out of scope:

- Vulnerabilities in third-party feeds or services phishnet connects to
- Issues that require physical access to the machine running phishnet
- Findings from automated scanners with no proof of exploitability

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities by email to: **research@oz-security.io**

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (sanitize any real phishing URLs or credentials)
- The version or commit hash you tested against

You will receive an acknowledgement within **72 hours**. If a fix is warranted, a patched release will be prepared and you will be credited (unless you prefer to remain anonymous).

## Responsible Disclosure

We follow a coordinated disclosure model. Please allow reasonable time for a fix to be developed and released before any public disclosure.
