# Contributing to phishnet

Thank you for your interest in contributing. phishnet is a security research tool — contributions that improve collection reliability, analysis coverage, or operational safety are especially welcome.

## Before You Start

- Read the [README](README.md) to understand the architecture and data flow.
- Check [open issues](https://github.com/olizimmermann/phishnet/issues) to see if your idea or bug is already tracked.
- For significant changes, open an issue first to discuss the approach before writing code.

## What We Welcome

- Bug fixes and reliability improvements
- New feed formats or feed-ingestion improvements
- New fingerprinting or analysis fields
- Performance improvements (crawling, DB writes, memory)
- Documentation improvements
- New export targets or notification integrations

## What We Do Not Accept

- Features that facilitate unauthorized access or harm
- Changes that remove safety checks (e.g. SSL verification bypass controls, rate limiting)
- Hardcoded credentials or API keys of any kind

## Development Setup

```bash
git clone https://github.com/olizimmermann/phishnet.git
cd phishnet
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.yaml config.local.yaml  # keep local config out of git
```

Run a single collection cycle against your local config:

```bash
python collector.py --config config.local.yaml
```

## Coding Style

- Python 3.11+, no external dependencies beyond what is in `requirements.txt`
- Follow the existing code style — no linter is enforced, but keep it consistent
- Keep functions focused and small; prefer explicit over clever
- Add a comment when the logic is not immediately obvious
- Use `logging` (not `print`) for all diagnostic output

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/feed-csv-parser
   ```
2. Make your changes. If you added or changed behavior, update `README.md` in the same commit.
3. Test your change manually — run a full collection cycle and verify the output.
4. Open a pull request against `main`. Fill in the PR template.

## Commit Messages

Use the imperative mood and keep the subject line under 72 characters:

```
fix: handle CSV feeds with BOM prefix
feat: add per-feed request timeout override
docs: document batch_size config key
```

Prefix options: `fix`, `feat`, `docs`, `refactor`, `perf`, `chore`

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md). Include your Python version, OS, and a sanitized snippet of the log output.

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Questions

Open a [discussion](https://github.com/olizimmermann/phishnet/discussions) or reach out at research@oz-security.io.
