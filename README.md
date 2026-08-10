# repo-secret-scanner

Scan a directory tree for hardcoded secrets before they reach a remote. Combines
high-signal vendor patterns (cloud keys, tokens, private keys) with a generic
assignment + Shannon-entropy check. Matches are always redacted in output, so
the scanner never prints a full secret. Pure Python standard library, no
dependencies.

> **Goal:** a fast pre-commit / CI grep that catches the obvious leaks (AWS keys,
> private keys, tokens, high-entropy passwords) without shipping a full toolchain.

## What it does

- Walks a tree, skipping binaries and noisy dirs (`.git`, `node_modules`, `.venv`, `dist`, ...)
- Vendor patterns: AWS access/secret keys, GitHub tokens/PATs, Slack tokens & webhooks, Google API keys, Stripe live keys, JWTs, PEM private-key blocks
- Generic detection: `key = value` where the key looks sensitive and the value has high entropy
- Ignores obvious placeholders (`changeme`, `example`, `<...>`, etc.)
- Inline allowlist: append `# allowlist secret` to a line to suppress it
- Redacted, severity-ranked output; optional JSON; `--fail-on` for CI gating

## Files

- `secret_scanner.py` - CLI and scanning engine
- `samples/config.env.sample` - synthetic file (AWS-documented examples) to demo detection
- `test_secret_scanner.py` - unit tests

## Usage

```bash
python3 secret_scanner.py .                       # scan current tree
python3 secret_scanner.py samples/ --json out.json
python3 secret_scanner.py . --fail-on high --exclude fixtures
```

## Test

```bash
python3 -m unittest -v
```

## Disclaimer

This repository reflects personal study and practice. It contains no real
secrets; sample values are AWS-documented examples and placeholders. This is a
lightweight aid, not a replacement for a dedicated secret-scanning platform.
Provided as-is; validate against your own context.

## License

MIT. See [LICENSE](LICENSE).
