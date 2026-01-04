#!/usr/bin/env python3
"""Manage GPG-encrypted secrets in TOML format."""

import argparse
import getpass
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

__version__ = "0.1.0"

CONFIG_DIR = Path.home() / ".config" / "my-secrets"
CONFIG_FILE = CONFIG_DIR / "config.toml"
DEFAULT_SECRETS_FILE = CONFIG_DIR / "secrets.gpg"


class Color:
    """ANSI color codes."""
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    GRAY = "\033[90m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


@dataclass
class Config:
    """Application configuration."""
    gpg_recipient: str
    secrets_file: Path


def load_config() -> Optional[Config]:
    """Load configuration from file. Returns None if not initialized."""
    if CONFIG_FILE.exists():
        try:
            content = CONFIG_FILE.read_text()
            data = tomllib.loads(content)
            gpg_recipient = data.get("gpg_recipient")
            if not gpg_recipient:
                return None
            return Config(
                gpg_recipient=gpg_recipient,
                secrets_file=Path(data.get("secrets_file", str(DEFAULT_SECRETS_FILE))).expanduser()
            )
        except Exception:
            pass
    return None


def require_config() -> Config:
    """Load config or exit with error if not initialized."""
    config = load_config()
    if config is None:
        print(f"{Color.RED}Not initialized. Run 'my-secrets init' first.{Color.RESET}", file=sys.stderr)
        sys.exit(1)
    return config


def save_config(gpg_email: str, secrets_file: Path, gpg_name: str = "", gpg_key_id: str = "") -> None:
    """Save configuration to file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if gpg_name and gpg_key_id:
        gpg_line = f'gpg_recipient = "{gpg_email}"  # {gpg_name}, {gpg_key_id}'
    else:
        gpg_line = f'gpg_recipient = "{gpg_email}"'
    content = f'{gpg_line}\nsecrets_file = "{secrets_file}"\n'
    CONFIG_FILE.write_text(content)


def list_gpg_keys() -> List[Dict[str, str]]:
    """List available GPG keys."""
    result = subprocess.run(
        ["gpg", "--list-keys", "--with-colons"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        return []

    keys = []
    current_key = {}
    for line in result.stdout.split("\n"):
        parts = line.split(":")
        if parts[0] == "pub":
            if current_key:
                keys.append(current_key)
            current_key = {"id": parts[4][-8:] if len(parts) > 4 else ""}
        elif parts[0] == "uid" and current_key:
            if "name" not in current_key:
                uid = parts[9] if len(parts) > 9 else ""
                current_key["uid"] = uid
                # Parse "Name <email>"
                match = re.match(r"(.+?)\s*<(.+?)>", uid)
                if match:
                    current_key["name"] = match.group(1).strip()
                    current_key["email"] = match.group(2).strip()
                else:
                    current_key["name"] = uid
                    current_key["email"] = ""
    if current_key:
        keys.append(current_key)

    return keys


def find_gpg_key(search: str) -> Optional[Dict[str, str]]:
    """Find a GPG key by name, email, or key ID. Returns full key info or None."""
    keys = list_gpg_keys()
    for key in keys:
        if search in (key.get("name", ""), key.get("email", ""), key.get("id", "")):
            return key
    return None


def create_gpg_key(name: str, email: str) -> Optional[str]:
    """Create a new GPG key and return the key ID."""
    print(f"{Color.GRAY}Generating GPG key...{Color.RESET}")
    print(f"{Color.GRAY}You may be prompted for a passphrase.{Color.RESET}\n")

    # Run gpg interactively with quick generate (uses GPG defaults for algorithm and expiration)
    result = subprocess.run(
        ["gpg", "--quick-gen-key", f"{name} <{email}>"],
    )

    if result.returncode != 0:
        print(f"{Color.RED}Failed to create key.{Color.RESET}", file=sys.stderr)
        return None

    # Get the newly created key
    keys = list_gpg_keys()
    for key in keys:
        if key.get("email") == email:
            return key.get("id")

    return None


def decrypt_secrets() -> str:
    """Decrypt the secrets file and return its content."""
    config = require_config()

    if not config.secrets_file.exists():
        return ""

    env = os.environ.copy()
    if "GPG_TTY" not in env:
        try:
            env["GPG_TTY"] = os.popen("tty").read().strip() or "/dev/tty"
        except Exception:
            env["GPG_TTY"] = "/dev/tty"

    result = subprocess.run(
        ["gpg", "--decrypt", "--quiet", str(config.secrets_file)],
        capture_output=True,
        text=True,
        env=env
    )

    if result.returncode != 0:
        if "No secret key" in result.stderr:
            print(f"{Color.RED}Error: GPG key '{config.gpg_recipient}' not found{Color.RESET}", file=sys.stderr)
            sys.exit(1)
        elif "decryption failed" in result.stderr:
            print(f"{Color.RED}Error: Decryption failed - check GPG agent{Color.RESET}", file=sys.stderr)
            sys.exit(1)
        return ""

    return result.stdout


def encrypt_secrets(content: str, config: Optional[Config] = None) -> None:
    """Encrypt content and write to secrets file."""
    if config is None:
        config = require_config()

    config.secrets_file.parent.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["gpg", "--encrypt", "--recipient", config.gpg_recipient, "--output", str(config.secrets_file), "--yes"],
        input=content,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"{Color.RED}Error encrypting: {result.stderr}{Color.RESET}", file=sys.stderr)
        sys.exit(1)


def parse_secrets(content: str) -> Dict[str, Dict[str, str]]:
    """Parse TOML content into a nested dictionary."""
    if not content.strip():
        return {}

    try:
        return tomllib.loads(content)
    except tomllib.TOMLDecodeError as e:
        print(f"{Color.RED}Error parsing secrets file: {e}{Color.RESET}", file=sys.stderr)
        sys.exit(1)


def serialize_toml(data: Dict[str, Dict[str, str]]) -> str:
    """Serialize dictionary to TOML format."""
    lines = []

    for section in sorted(data.keys()):
        values = data[section]
        if not isinstance(values, dict):
            continue

        lines.append(f"[{section}]")
        for key in sorted(values.keys()):
            value = values[key]
            if isinstance(value, str):
                escaped = value.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace('"', '\\"')
                lines.append(f'{key} = "{escaped}"')
            elif isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")
            elif isinstance(value, (int, float)):
                lines.append(f"{key} = {value}")
            else:
                escaped = str(value).replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r").replace('"', '\\"')
                lines.append(f'{key} = "{escaped}"')
        lines.append("")

    return "\n".join(lines)


def load_secrets() -> Dict[str, Dict[str, str]]:
    """Load and parse secrets from encrypted file."""
    content = decrypt_secrets()
    return parse_secrets(content)


def save_secrets(secrets: Dict[str, Dict[str, str]]) -> None:
    """Serialize and encrypt secrets to file."""
    content = serialize_toml(secrets)
    encrypt_secrets(content)


def validate_secrets_structure(secrets: Dict) -> tuple[List[str], List[str]]:
    """Validate secrets structure and naming. Returns (errors, warnings)."""
    errors = []
    warnings = []
    key_pattern = re.compile(r'^[A-Z][A-Z0-9_]*$')

    for section, values in secrets.items():
        if '.' in section:
            errors.append(f"[{section}]: category name cannot contain dots")

        if not isinstance(values, dict):
            errors.append(f"[{section}] is not a valid category (expected table)")
            continue

        for key, value in values.items():
            if not isinstance(value, str):
                errors.append(f"[{section}].{key}: value must be string, got {type(value).__name__}")
            if not key_pattern.match(key):
                warnings.append(f"[{section}].{key}: key should be UPPER_SNAKE_CASE")

    return errors, warnings


def cmd_list(args: argparse.Namespace) -> int:
    """List all secrets or filter by category."""
    secrets = load_secrets()

    if not secrets:
        print(f"{Color.GRAY}No secrets found.{Color.RESET}")
        return 0

    # List only category names with counts
    if args.categories:
        for section in sorted(secrets.keys()):
            count = len(secrets[section])
            print(f"{Color.CYAN}●{Color.RESET} {section} {Color.GRAY}({count} secret{'s' if count != 1 else ''}){Color.RESET}")
        return 0

    # List secrets in specific category
    if args.category:
        if args.category not in secrets:
            print(f"{Color.RED}Category '{args.category}' not found.{Color.RESET}", file=sys.stderr)
            return 1
        print(f"{Color.CYAN}[{args.category}]{Color.RESET}")
        for key in sorted(secrets[args.category].keys()):
            print(f"  {key}")
        return 0

    # List all secrets
    for section in sorted(secrets.keys()):
        print(f"{Color.CYAN}[{section}]{Color.RESET}")
        for key in sorted(secrets[section].keys()):
            print(f"  {key}")
        print()

    return 0


def cmd_get(args: argparse.Namespace) -> int:
    """Get a specific secret value."""
    secrets = load_secrets()

    if args.category not in secrets:
        print(f"{Color.RED}Category '{args.category}' not found.{Color.RESET}", file=sys.stderr)
        return 1

    if args.name not in secrets[args.category]:
        print(f"{Color.RED}Secret '{args.name}' not found in '{args.category}'.{Color.RESET}", file=sys.stderr)
        return 1

    print(secrets[args.category][args.name])
    return 0


def cmd_set(args: argparse.Namespace) -> int:
    """Set a secret value."""
    # Validate category name (no dots allowed in TOML section names)
    if '.' in args.category:
        print(f"{Color.RED}Error: category name cannot contain dots{Color.RESET}", file=sys.stderr)
        return 1

    # Validate key naming
    key_pattern = re.compile(r'^[A-Z][A-Z0-9_]*$')
    if not key_pattern.match(args.name):
        print(f"{Color.YELLOW}Warning: '{args.name}' should be UPPER_SNAKE_CASE{Color.RESET}")

    secrets = load_secrets()

    if args.value:
        value = args.value
    else:
        value = getpass.getpass(f"Enter value for {args.category}/{args.name}: ")
        if not value:
            print(f"{Color.YELLOW}Cancelled - empty value.{Color.RESET}")
            return 1

    if args.category not in secrets:
        secrets[args.category] = {}

    is_update = args.name in secrets[args.category]
    secrets[args.category][args.name] = value

    save_secrets(secrets)

    action = "Updated" if is_update else "Created"
    print(f"{Color.GREEN}✓ {action} {args.category}/{args.name}{Color.RESET}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    """Delete a secret."""
    secrets = load_secrets()

    if args.category not in secrets:
        print(f"{Color.RED}Category '{args.category}' not found.{Color.RESET}", file=sys.stderr)
        return 1

    if args.name not in secrets[args.category]:
        print(f"{Color.RED}Secret '{args.name}' not found in '{args.category}'.{Color.RESET}", file=sys.stderr)
        return 1

    if not args.force:
        confirm = input(f"Delete {args.category}/{args.name}? [y/N]: ")
        if confirm.lower() != 'y':
            print(f"{Color.GRAY}Cancelled.{Color.RESET}")
            return 0

    del secrets[args.category][args.name]

    # Remove empty category
    if not secrets[args.category]:
        del secrets[args.category]

    save_secrets(secrets)

    print(f"{Color.GREEN}✓ Deleted {args.category}/{args.name}{Color.RESET}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Search secrets by pattern."""
    secrets = load_secrets()

    try:
        pattern = re.compile(args.pattern, re.IGNORECASE)
    except re.error as e:
        print(f"{Color.RED}Invalid regex pattern: {e}{Color.RESET}", file=sys.stderr)
        return 1

    found: List[str] = []
    for section, values in sorted(secrets.items()):
        for key in sorted(values.keys()):
            if pattern.search(key) or pattern.search(section):
                found.append(f"{section}/{key}")

    if not found:
        print(f"{Color.GRAY}No matches found.{Color.RESET}")
        return 0

    for match in found:
        print(f"{Color.GREEN}●{Color.RESET} {match}")

    print(f"\n{Color.GRAY}{len(found)} match{'es' if len(found) != 1 else ''} found.{Color.RESET}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """Export secrets as shell export statements or full TOML."""
    content = decrypt_secrets()
    secrets = parse_secrets(content)

    # Export full TOML for backup
    if args.all:
        if content:
            print(content, end="")
        return 0

    # Export category as shell statements
    if not args.category:
        print(f"{Color.RED}Category required (or use --all for full TOML){Color.RESET}", file=sys.stderr)
        return 1

    if args.category not in secrets:
        print(f"{Color.RED}Category '{args.category}' not found.{Color.RESET}", file=sys.stderr)
        return 1

    for key, value in sorted(secrets[args.category].items()):
        escaped = str(value).replace("'", "'\\''")
        print(f"export {key}='{escaped}'")

    return 0


def select_gpg_key_interactive() -> Optional[Dict[str, str]]:
    """Interactive GPG key selection. Returns full key info or None if cancelled."""
    keys = list_gpg_keys()

    print(f"\n{Color.BOLD}Available GPG keys:{Color.RESET}")
    if keys:
        for i, key in enumerate(keys, 1):
            name = key.get("name", "Unknown")
            email = key.get("email", "")
            key_id = key.get("id", "")
            if email:
                print(f"  {Color.CYAN}{i}.{Color.RESET} {name} <{email}> [{key_id}]")
            else:
                print(f"  {Color.CYAN}{i}.{Color.RESET} {name} [{key_id}]")
        print(f"  {Color.CYAN}{len(keys) + 1}.{Color.RESET} [Create new key]")
    else:
        print(f"  {Color.GRAY}No keys found.{Color.RESET}")
        print(f"  {Color.CYAN}1.{Color.RESET} [Create new key]")

    # Select key
    default = "1"
    try:
        choice = input(f"\nSelect key [{default}]: ").strip() or default
        choice_num = int(choice)
    except (ValueError, KeyboardInterrupt):
        print(f"\n{Color.GRAY}Cancelled.{Color.RESET}")
        return None

    # Handle key selection
    if keys and 1 <= choice_num <= len(keys):
        return keys[choice_num - 1]
    elif choice_num == len(keys) + 1 or (not keys and choice_num == 1):
        # Create new key
        print(f"\n{Color.BOLD}Create new GPG key:{Color.RESET}")
        try:
            name = input("  Name: ").strip()
            email = input("  Email: ").strip()
        except KeyboardInterrupt:
            print(f"\n{Color.GRAY}Cancelled.{Color.RESET}")
            return None

        if not name or not email:
            print(f"{Color.RED}Name and email are required.{Color.RESET}")
            return None

        key_id = create_gpg_key(name, email)
        if not key_id:
            return None

        print(f"{Color.GREEN}✓ Created GPG key: {key_id}{Color.RESET}")
        return {"name": name, "email": email, "id": key_id}
    else:
        print(f"{Color.RED}Invalid selection.{Color.RESET}")
        return None


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize a new secrets file with interactive setup."""
    secrets_file = args.secrets_file.expanduser() if args.secrets_file else DEFAULT_SECRETS_FILE

    # Validate GPG key early if provided
    gpg_key_info = None
    if args.gpg_key:
        gpg_key_info = find_gpg_key(args.gpg_key)
        if gpg_key_info is None:
            print(f"{Color.RED}Error: GPG key '{args.gpg_key}' not found{Color.RESET}", file=sys.stderr)
            return 1

    print(f"\n{Color.BOLD}Secrets file:{Color.RESET} {secrets_file}")

    # Check for existing secrets
    if secrets_file.exists() and not args.force:
        print(f"{Color.YELLOW}Secrets file already exists: {secrets_file}{Color.RESET}")
        confirm = input("Reinitialize? This will overwrite existing secrets. [y/N]: ")
        if confirm.lower() != 'y':
            print(f"{Color.GRAY}Cancelled.{Color.RESET}")
            return 0

    if gpg_key_info is None:
        gpg_key_info = select_gpg_key_interactive()
        if gpg_key_info is None:
            return 1

    gpg_email = gpg_key_info.get("email", "")
    gpg_name = gpg_key_info.get("name", "")
    gpg_key_id = gpg_key_info.get("id", "")

    # Save config
    save_config(gpg_email, secrets_file, gpg_name, gpg_key_id)
    print(f"{Color.GREEN}✓ Saved config: {CONFIG_FILE}{Color.RESET}")

    # Create empty secrets file
    config = Config(gpg_recipient=gpg_email, secrets_file=secrets_file)
    encrypt_secrets("", config)

    print(f"{Color.GREEN}✓ Initialized secrets file: {secrets_file}{Color.RESET}")
    print(f"{Color.GRAY}GPG recipient: {gpg_email}{Color.RESET}")
    return 0


def cmd_config(args: argparse.Namespace) -> int:
    """View or modify configuration."""
    config = load_config()

    if config is None:
        print(f"{Color.RED}Not initialized. Run 'my-secrets init' first.{Color.RESET}", file=sys.stderr)
        return 1

    # Show current config if no options
    if args.gpg_key is None and not args.secrets_file:
        # Look up full key info
        key_info = find_gpg_key(config.gpg_recipient)
        if key_info:
            name = key_info.get("name", "")
            key_id = key_info.get("id", "")
            print(f"gpg_recipient = {config.gpg_recipient}  # {name}, {key_id}")
        else:
            print(f"gpg_recipient = {config.gpg_recipient}")
        print(f"secrets_file = {config.secrets_file}")
        return 0

    new_key_info: Optional[Dict[str, str]] = None
    new_secrets_file = config.secrets_file

    # Handle --gpg-key (with or without value)
    if args.gpg_key is not None:
        # Decrypt with old key first
        content = decrypt_secrets()

        if args.gpg_key == "":
            # Interactive selection
            new_key_info = select_gpg_key_interactive()
            if new_key_info is None:
                return 0  # Cancelled
        else:
            # Validate key exists
            new_key_info = find_gpg_key(args.gpg_key)
            if new_key_info is None:
                print(f"{Color.RED}Error: GPG key '{args.gpg_key}' not found{Color.RESET}", file=sys.stderr)
                return 1

        # Re-encrypt with new key
        new_email = new_key_info.get("email", "")
        temp_config = Config(gpg_recipient=new_email, secrets_file=config.secrets_file)
        encrypt_secrets(content, temp_config)
        print(f"{Color.GREEN}✓ Secrets re-encrypted with new key{Color.RESET}")

    # Handle --secrets-file
    if args.secrets_file:
        new_secrets_file = args.secrets_file.expanduser()

    # Save config with full key info if changed, otherwise just update secrets_file
    if new_key_info:
        save_config(new_key_info.get("email", ""), new_secrets_file,
                    new_key_info.get("name", ""), new_key_info.get("id", ""))
    else:
        save_config(config.gpg_recipient, new_secrets_file)
    print(f"{Color.GREEN}✓ Config updated{Color.RESET}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    """Import secrets from a TOML file."""
    file_path = Path(args.file)

    if not file_path.exists():
        print(f"{Color.RED}File not found: {file_path}{Color.RESET}", file=sys.stderr)
        return 1

    try:
        content = file_path.read_text()
        secrets = tomllib.loads(content)
    except tomllib.TOMLDecodeError as e:
        print(f"{Color.RED}Invalid TOML file: {e}{Color.RESET}", file=sys.stderr)
        return 1

    # Validate structure and naming
    errors, warnings = validate_secrets_structure(secrets)

    if errors:
        print(f"{Color.RED}Validation errors:{Color.RESET}", file=sys.stderr)
        for error in errors:
            print(f"  {Color.RED}● {error}{Color.RESET}", file=sys.stderr)
        return 1

    if warnings:
        print(f"{Color.YELLOW}Validation warnings:{Color.RESET}")
        for warning in warnings:
            print(f"  {Color.YELLOW}● {warning}{Color.RESET}")
        print()

    # Count secrets
    count = sum(len(v) for v in secrets.values() if isinstance(v, dict))

    if not args.force:
        existing = load_secrets()
        if existing:
            print(f"{Color.YELLOW}Warning: This will replace existing secrets.{Color.RESET}")
        confirm = input(f"Import {count} secrets from {file_path}? [y/N]: ")
        if confirm.lower() != 'y':
            print(f"{Color.GRAY}Cancelled.{Color.RESET}")
            return 0

    encrypt_secrets(content)
    print(f"{Color.GREEN}✓ Imported {count} secrets from {file_path}{Color.RESET}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="my-secrets",
        description="Manage GPG-encrypted secrets in TOML format.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", title="commands", metavar="")

    # init command
    init_parser = subparsers.add_parser("init", help="Initialize new secrets file")
    init_parser.add_argument("-f", "--force", action="store_true", help="Overwrite existing file")
    init_parser.add_argument("-s", "--secrets-file", type=Path, help="Custom path for secrets file")
    init_parser.add_argument("--gpg-key", help="GPG recipient (skip interactive selection)")
    init_parser.set_defaults(func=cmd_init)

    # config command
    config_parser = subparsers.add_parser("config", help="View or modify configuration")
    config_parser.add_argument("--gpg-key", nargs="?", const="", help="Set GPG recipient (interactive if no value)")
    config_parser.add_argument("--secrets-file", type=Path, help="Set secrets file path")
    config_parser.set_defaults(func=cmd_config)

    # list command
    list_parser = subparsers.add_parser("list", help="List secrets")
    list_parser.add_argument("category", nargs="?", help="Filter by category")
    list_parser.add_argument("-c", "--categories", action="store_true", help="List only category names")
    list_parser.set_defaults(func=cmd_list)

    # get command
    get_parser = subparsers.add_parser("get", help="Get a secret value")
    get_parser.add_argument("category", help="Secret category")
    get_parser.add_argument("name", help="Secret name")
    get_parser.set_defaults(func=cmd_get)

    # set command
    set_parser = subparsers.add_parser("set", help="Set a secret value")
    set_parser.add_argument("category", help="Secret category")
    set_parser.add_argument("name", help="Secret name")
    set_parser.add_argument("value", nargs="?", help="Secret value (prompts if not provided)")
    set_parser.set_defaults(func=cmd_set)

    # delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a secret")
    delete_parser.add_argument("category", help="Secret category")
    delete_parser.add_argument("name", help="Secret name")
    delete_parser.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    delete_parser.set_defaults(func=cmd_delete)

    # search command
    search_parser = subparsers.add_parser("search", help="Search secrets by pattern")
    search_parser.add_argument("pattern", help="Regex pattern to search")
    search_parser.set_defaults(func=cmd_search)

    # export command
    export_parser = subparsers.add_parser("export", help="Export as shell statements")
    export_parser.add_argument("category", nargs="?", help="Category to export")
    export_parser.add_argument("-a", "--all", action="store_true", help="Export full TOML file for backup")
    export_parser.set_defaults(func=cmd_export)

    # import command
    import_parser = subparsers.add_parser("import", help="Import from TOML file")
    import_parser.add_argument("file", help="TOML file to import")
    import_parser.add_argument("-f", "--force", action="store_true", help="Skip confirmation")
    import_parser.set_defaults(func=cmd_import)

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
