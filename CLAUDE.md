# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
uv pip install -e ".[dev]"   # Install in development mode
poe clean                     # Clean build artifacts
poe build                     # Build package
```

## Architecture

Single-file CLI tool (`my_secrets.py`) that manages GPG-encrypted secrets stored in TOML format.

### Key Components

- **Config**: Stored at `~/.config/my-secrets.toml`, contains `gpg_recipient` and `secrets_file` path
- **Secrets**: Encrypted with GPG at `~/.my/secrets.gpg`, decrypted TOML with `[category]` sections
- **Commands**: `init`, `list`, `get`, `set`, `delete`, `search`, `export`, `import`

### Data Flow

1. `load_config()` / `require_config()` - reads config or exits if not initialized
2. `decrypt_secrets()` - calls GPG to decrypt, returns TOML string
3. `parse_secrets()` - uses `tomllib` to parse TOML into dict
4. `serialize_toml()` - manual TOML serialization (no external deps)
5. `encrypt_secrets()` - calls GPG to encrypt and write

### GPG Integration

- Uses system `gpg` command via `subprocess`
- `list_gpg_keys()` parses `gpg --list-keys --with-colons` output
- `create_gpg_key()` uses `gpg --quick-gen-key` for interactive key creation

## Testing

Use `secrets.toml` as example input for import testing:
```bash
my-secrets import secrets.toml
```
