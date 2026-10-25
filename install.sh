#!/usr/bin/env bash
set -e

SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
fi

GEMINI_CONFIG_DIR="$HOME/.gemini/config"
SCRIPTS_DIR="$GEMINI_CONFIG_DIR/scripts"
CLI_SETTINGS_DIR="$HOME/.gemini/antigravity-cli"
SETTINGS_FILE="$CLI_SETTINGS_DIR/settings.json"
HOOKS_FILE="$GEMINI_CONFIG_DIR/hooks.json"
REPO_RAW_URL="${AIRLOCK_RAW_URL:-https://raw.githubusercontent.com/danny/airlock/main}"

mkdir -p "$SCRIPTS_DIR"
mkdir -p "$CLI_SETTINGS_DIR"

download_file() {
    local url="$1"
    local dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        echo "❌ Error: curl or wget is required to download scripts." >&2
        exit 1
    fi
}

# Copy or download the Airlock approval hook, daemon, and modular package
if [ -n "$SCRIPT_DIR" ] && [ -d "$SCRIPT_DIR/airlock" ]; then
    rm -rf "$SCRIPTS_DIR/airlock"
    cp -r "$SCRIPT_DIR/airlock" "$SCRIPTS_DIR/"
    cp "$SCRIPT_DIR/scripts/airlock_hook.py" "$SCRIPTS_DIR/"
    cp "$SCRIPT_DIR/scripts/airlock_daemon.py" "$SCRIPTS_DIR/"
    # Also copy backward-compatibility shims
    [ -f "$SCRIPT_DIR/scripts/lgtm_hook.py" ] && cp "$SCRIPT_DIR/scripts/lgtm_hook.py" "$SCRIPTS_DIR/"
    [ -f "$SCRIPT_DIR/scripts/lgtm_daemon.py" ] && cp "$SCRIPT_DIR/scripts/lgtm_daemon.py" "$SCRIPTS_DIR/"
elif [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/scripts/airlock_hook.py" ]; then
    cp "$SCRIPT_DIR/scripts/airlock_hook.py" "$SCRIPTS_DIR/"
    cp "$SCRIPT_DIR/scripts/airlock_daemon.py" "$SCRIPTS_DIR/"
else
    echo "Downloading Airlock scripts..."
    download_file "$REPO_RAW_URL/scripts/airlock_hook.py" "$SCRIPTS_DIR/airlock_hook.py"
    download_file "$REPO_RAW_URL/scripts/airlock_daemon.py" "$SCRIPTS_DIR/airlock_daemon.py"
fi

chmod +x "$SCRIPTS_DIR/airlock_hook.py" "$SCRIPTS_DIR/airlock_daemon.py" 2>/dev/null || true
[ -f "$SCRIPTS_DIR/lgtm_hook.py" ] && chmod +x "$SCRIPTS_DIR/lgtm_hook.py" 2>/dev/null || true
[ -f "$SCRIPTS_DIR/lgtm_daemon.py" ] && chmod +x "$SCRIPTS_DIR/lgtm_daemon.py" 2>/dev/null || true

# Update Antigravity settings to always-proceed
PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [ -n "$PYTHON_BIN" ]; then
    if [ -f "$SETTINGS_FILE" ]; then
        cp "$SETTINGS_FILE" "$SETTINGS_FILE.bak"
    fi
    "$PYTHON_BIN" -c '
import json, sys, os
path = sys.argv[1]
os.makedirs(os.path.dirname(path), exist_ok=True)
data = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
data["toolPermission"] = "always-proceed"
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
' "$SETTINGS_FILE"
else
    echo "⚠️  Python not found; please manually set \"toolPermission\": \"always-proceed\" in $SETTINGS_FILE" >&2
fi

# Configure the pre-tool hook in Antigravity
if [ -f "$HOOKS_FILE" ]; then
    cp "$HOOKS_FILE" "$HOOKS_FILE.bak"
fi

cat << 'EOF' > "$HOOKS_FILE"
{
  "airlock-hook": {
    "PreToolUse": [
      {
        "matcher": "run_command",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.gemini/config/scripts/airlock_hook.py",
            "timeout": 45
          }
        ]
      }
    ]
  }
}
EOF

echo "✅ Airlock installed! All run_command tool calls will now be evaluated with multi-tier high assurance."
