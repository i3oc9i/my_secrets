# my-secrets

A command-line tool for securely managing secrets like API keys, tokens, and passwords. Secrets are stored in a simple TOML format, encrypted with GPG, and organized into categories for easy access. Export secrets as shell variables or back them up as plain TOML files.

## Installation

```bash
uv pip install -e .
```

## Initialization

Before using my-secrets, run the interactive setup:

```bash
my-secrets init
```

This will:
1. List available GPG keys on your system
2. Let you select an existing key or create a new one
3. Create the config and encrypted secrets file

### Init Options

```bash
my-secrets init                          # Interactive GPG key selection
my-secrets init --gpg-key user@email.com # Use specific GPG key
my-secrets init --gpg-key "User Name"    # Select by name
my-secrets init -s ~/secrets.gpg         # Custom secrets file location
my-secrets init -f                       # Force reinitialize (overwrite)
```

### Files Created

```
~/.config/my-secrets/
├── config.toml      # Configuration (GPG key, secrets path)
└── secrets.gpg      # Encrypted secrets (or custom path with -s)
```

## Usage

```bash
my-secrets list                    # List all categories and keys
my-secrets list -c                 # List only category names
my-secrets list work               # List keys in [work] section
my-secrets get work GITHUB_TOKEN   # Get secret value
my-secrets set work API_KEY        # Prompt for value securely
my-secrets set work API_KEY "val"  # Set value directly
my-secrets delete work OLD_KEY     # Delete with confirmation
my-secrets delete -f work OLD_KEY  # Delete without confirmation
my-secrets search TOKEN            # Regex search across all secrets
my-secrets export database         # Output: export KEY='value'
my-secrets export --all            # Export full TOML (for backup)
my-secrets import backup.toml      # Import from TOML file
my-secrets config                  # Show current configuration
my-secrets config --gpg-key        # Change GPG key (interactive)
my-secrets config --gpg-key EMAIL  # Change to specific GPG key
```

## Backup & Restore

```bash
# Backup
my-secrets export --all > backup.toml

# Restore
my-secrets import backup.toml
```

## Secrets Format

TOML with sections for categories, ENV-style naming:

```toml
[work]
GITHUB_TOKEN = "ghp_xxxx"
AWS_SECRET_KEY = "xxxx"

[database]
POSTGRES_PASSWORD = "xxxx"
REDIS_URL = "redis://localhost"
```

## Configuration

Config file: `~/.config/my-secrets/config.toml`

```toml
gpg_recipient = "your@email.com"  # Your Name, KEY_ID
secrets_file = "~/.config/my-secrets/secrets.gpg"
```

The GPG key can be specified by name, email, or key ID. The config stores the email with name and key ID as a comment for reference.

Use `my-secrets config --gpg-key` to change the GPG key (secrets are automatically re-encrypted).

## Requirements

- Python 3.12+
- GPG
