#!/usr/bin/env bash
# Install the loot skill and its slash commands for OpenCode or Claude Code.
set -euo pipefail

usage() {
  echo "usage: ./install.sh [--opencode | --claude] [--global | --project DIR]" >&2
  exit 2
}

target=opencode
root="$HOME"
scope=global
while [ $# -gt 0 ]; do
  case "$1" in
    --opencode) target=opencode ;;
    --claude) target=claude ;;
    --global) root="$HOME"; scope=global ;;
    --project) [ $# -ge 2 ] || usage; root="$(cd "$2" && pwd)"; scope=project; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
  shift
done

if ! command -v uv >/dev/null 2>&1; then
  echo "loot needs uv, which was not found on PATH. Install it with:" >&2
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
  exit 1
fi

src="$(cd "$(dirname "$0")" && pwd)"
skills="$root/.claude/skills"
dest="$skills/loot"

if [ -e "$dest" ] && ! grep -q '^name: loot$' "$dest/SKILL.md" 2>/dev/null; then
  echo "$dest exists and is not a loot install; not touching it" >&2
  exit 1
fi
mkdir -p "$skills"
rm -rf "$dest"
cp -R "$src/loot" "$dest"
find "$dest" -name __pycache__ -type d -prune -exec rm -rf {} +

loot_cmd="uv run -q --script \"$dest/scripts/loot.py\""

if [ "$target" = opencode ]; then
  if [ "$scope" = global ]; then commands="$HOME/.config/opencode/commands"; else commands="$root/.opencode/commands"; fi
  mkdir -p "$commands"
fi

installed=()
for file in "$src"/commands/loot-*.md; do
  verb="$(basename "$file" .md)"
  text="$(cat "$file")"
  text="${text//\{\{LOOT\}\}/$loot_cmd}"
  if [ "$target" = opencode ]; then
    printf '%s\n' "$text" > "$commands/$verb.md"
  else
    description="$(printf '%s\n' "$text" | sed -n 's/^description: //p' | head -n 1)"
    body="$(printf '%s\n' "$text" | awk 'c == 2 { print; next } /^---$/ { c++ }')"
    mkdir -p "$skills/$verb"
    {
      echo "---"
      echo "name: $verb"
      echo "description: $description"
      echo "disable-model-invocation: true"
      echo "metadata:"
      echo "  opencode/autoinvoke: \"false\""
      echo "---"
      printf '%s\n' "$body"
    } > "$skills/$verb/SKILL.md"
  fi
  installed+=("/$verb")
done

echo "Installed the loot skill to $dest"
if [ "$target" = opencode ]; then
  echo "Installed commands to $commands: ${installed[*]}"
  echo "Restart OpenCode, then try: /loot-init demo"
else
  echo "Installed commands as skills in $skills: ${installed[*]}"
  echo "Start Claude Code, then try: /loot-init demo"
fi
