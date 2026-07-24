# Shell conventions: PowerShell primary, Bash fallback

This machine has the PowerShell tool enabled (`CLAUDE_CODE_USE_POWERSHELL_TOOL=1` in user settings) and PowerShell 7+ (`pwsh`) installed alongside the Windows-builtin 5.1. **Default to the PowerShell tool for CLI operations in this repo.** Fall back to the Bash tool only when a PowerShell invocation errors and a Bash-native form is available — the Bash tool stays as the documented backup, not a deprecated path.

## Dual-write reference

Most CLI tools used in this repo (`gh`, `git`, `jq`) take identical arguments regardless of shell — only the shell-level syntax around them (multi-line strings, chaining) differs. Below are the patterns actually used in this repo's docs/skills.

### Multi-line issue/PR bodies (see `docs/agents/issue-tracker.md`)

Bash (heredoc):
```bash
gh issue create --title "Bug: X" --body "$(cat <<'EOF'
Line one.
Line two.
EOF
)"
```

PowerShell 7+ (here-string):
```powershell
$body = @'
Line one.
Line two.
'@
gh issue create --title "Bug: X" --body $body
```

### Chaining commands

Bash: `git add -A && git commit -m "msg"`

PowerShell 7+ supports `&&` / `||` natively (unlike Windows PowerShell 5.1), so the same line runs unchanged. If a script must also run on bare 5.1, use `cmd1; if ($?) { cmd2 }` instead.

### Everything else (jq filters, `git remote -v`, `gh issue list --jq '...'`)

Pass through unchanged — these are quoted arguments to an external binary, not shell syntax, so the same command line works under both tools.

## If PowerShell fails

Retry the same operation with the Bash tool before troubleshooting further. If the Bash retry also fails, the problem is almost certainly in the command itself, not the shell.
