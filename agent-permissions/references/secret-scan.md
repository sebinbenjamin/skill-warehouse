# Reach inventory commands

Run from the repo root. Report **names and locations only** (never values) so the report is not itself a leak. Install what is missing (`brew install gitleaks trufflehog`, `winget install gitleaks`, `pip install detect-secrets`); if a scanner cannot be installed, say so and fall back to the `find`/`git` checks.

```bash
# 1. Worktree scan INCLUDING untracked and ignored files — this is what the agent can read.
gitleaks dir -v --no-banner .

# 2. History scan — secrets deleted from HEAD are still readable via git log / git show.
gitleaks git -v --no-banner .

# 3. Live-credential triage: verified findings are active and must be rotated, not deleted.
trufflehog filesystem . --results=verified --no-update

# 4. What is on disk that git never sees.
git status --ignored --porcelain | head -50
find . \( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
  -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name '*.tfstate*' -o -name '*.har' \
  -o -name '.npmrc' -o -name '.netrc' -o -name 'serviceAccount*.json' -o -name '*credential*' \) \
  -not -path '*/node_modules/*' -not -path './.git/*'

# 5. Tokens hidden in git plumbing.
git remote -v
git config --local --list | grep -Ei 'url|token|password|insteadof|fsmonitor|hooks'

# 6. Symlinks that escape the repo.
find . -type l -not -path '*/node_modules/*' -exec ls -ld {} +

# 7. The shell the agent will inherit — names only.
env | grep -Ei '(_KEY|_TOKEN|_SECRET|_PASSWORD|_PASSWD|_CREDENTIAL|_DSN|_URL|_URI|^AWS_|^AZURE_|^GCP_|^GITHUB_|^GH_|^NPM_|^ANTHROPIC_|^OPENAI_|^GEMINI_|^VAULT_|^SSH_AUTH_SOCK)' | cut -d= -f1 | sort

# 8. Home credential stores and other agents' state (existence only).
ls -d ~/.ssh ~/.aws ~/.azure ~/.config/gcloud ~/.kube ~/.docker ~/.gnupg ~/.netrc ~/.git-credentials \
  ~/.config/gh ~/.npmrc ~/.pypirc ~/.claude ~/.claude.json ~/.codex ~/.gemini ~/.cursor ~/.config/opencode 2>/dev/null

# 9. Connected tools with ambient auth (exit status only; do not print identities into the report).
gh auth status >/dev/null 2>&1 && echo "gh: authenticated"
aws sts get-caller-identity >/dev/null 2>&1 && echo "aws: authenticated"
gcloud auth list --format='value(account)' 2>/dev/null | grep -q . && echo "gcloud: authenticated"
az account show >/dev/null 2>&1 && echo "az: authenticated"
kubectl config current-context 2>/dev/null | grep -q . && echo "kubectl: context set"
test -S /var/run/docker.sock && echo "docker.sock: reachable"

# 10. Cloud metadata endpoint (cloud dev boxes / CI runners).
curl -s -m 1 http://169.254.169.254/ >/dev/null 2>&1 && echo "IMDS: reachable"

# 11. Sibling repos under the parent directory (other owners' code in reach via ../).
ls -d ../*/.git 2>/dev/null | sed 's#/.git##'

# 12. Yolo flags anywhere in the repo or shell profiles.
grep -rEn -- '--dangerously-skip-permissions|--yolo|--full-auto|--dangerously-bypass|--trust-all-tools|--allow-all|--yes-always|opencode (run )?--auto|approval_policy *= *"never"|danger-full-access' \
  . ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile ~/.config/fish/config.fish \
  "$HOME/Documents/PowerShell/Microsoft.PowerShell_profile.ps1" 2>/dev/null | grep -v node_modules
```

PowerShell equivalents where the Bash tool is unavailable: `Get-ChildItem Env: | Where-Object Name -match '_KEY|_TOKEN|_SECRET|...' | Select-Object -ExpandProperty Name`; `Get-ChildItem -Recurse -Force -Include .env*,*.pem,*.key`; history file at `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`.

Interpretation:

- A finding in **history only** is still Critical: the agent can run `git log -p`.
- **Deletion is not remediation.** A verified live credential requires rotation or revocation.
- Clean scans mean "no known-pattern secret found". They say nothing about personal data in fixtures, confidential source, or internal architecture; that is the `repo-disclosure` skill's question.
- A `.gitignore` entry proves nothing about reach; an ignored file is as readable as a tracked one.
