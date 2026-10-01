#!/usr/bin/env bash
# Ubuntu 26.04: dedicated host user + rootless Podman for coding agents.
# Run as your normal desktop user: bash setup-ai-workbench.sh
set -Eeuo pipefail

AGENT_USER=aiagent
MARKER='# Managed by setup-ai-workbench.sh'
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }
case ${1:-} in
    '') FINISH_ONLY=0 ;;
    --finish) FINISH_ONLY=1 ;;
    *) die 'Usage: bash setup-ai-workbench.sh [--finish]' ;;
esac

[[ $EUID -ne 0 ]] || die 'Run as your normal login user, not root.'
[[ $(. /etc/os-release; printf '%s' "$ID") == ubuntu ]] || die 'This script targets Ubuntu.'
[[ $(. /etc/os-release; printf '%s' "$VERSION_ID") == 26.04 ]] || die 'This script targets Ubuntu 26.04; review it before using another release.'
LOGIN_USER=$(id -un)
[[ $LOGIN_USER =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || die 'Unsupported login name.'
LOGIN_HOME=$(getent passwd "$LOGIN_USER" | cut -d: -f6)
[[ $HOME == "$LOGIN_HOME" && -d $LOGIN_HOME ]] || die 'Run from your normal login session.'
PROJECTS=$LOGIN_HOME/projects
[[ ! -L $PROJECTS ]] || die 'The projects directory must not be a symlink.'
[[ ! -e $PROJECTS || -d $PROJECTS ]] || die 'The projects path exists but is not a directory.'

say "Preparing $LOGIN_USER and $AGENT_USER"
sudo -v
if (( ! FINISH_ONLY )); then
    sudo apt-get update
    sudo apt-get install -y podman uidmap slirp4netns passt fuse-overlayfs acl git ca-certificates
fi

if ! id "$AGENT_USER" >/dev/null 2>&1; then
    sudo adduser --disabled-password --gecos 'AI Agent Runtime' "$AGENT_USER"
fi
AGENT_HOME=$(getent passwd "$AGENT_USER" | cut -d: -f6)
[[ $AGENT_HOME == "/home/$AGENT_USER" ]] || die 'Existing aiagent account has an unexpected home.'
[[ $(getent passwd "$AGENT_USER" | cut -d: -f3) -ge 1000 ]] || die 'aiagent must be an ordinary unprivileged user.'
for group in sudo adm docker libvirt lxd; do
    if id -nG "$AGENT_USER" | tr ' ' '\n' | grep -Fxq "$group"; then
        die "Remove aiagent from privileged group $group before proceeding."
    fi
done
grep -q "^$AGENT_USER:" /etc/subuid || die 'No subordinate UID range for aiagent.'
grep -q "^$AGENT_USER:" /etc/subgid || die 'No subordinate GID range for aiagent.'

say "Granting access to $PROJECTS"
mkdir -p -- "$PROJECTS"
sudo setfacl -m "u:$AGENT_USER:--x" "$LOGIN_HOME"
# Two-way ACLs: the agent can edit existing projects; both users can edit new files.
sudo setfacl -R -m "u:$AGENT_USER:rwX" "$PROJECTS"
sudo find "$PROJECTS" -type d -exec setfacl -m "d:u:$AGENT_USER:rwx,d:u:$LOGIN_USER:rwx" {} +

say 'Enabling the unprivileged Podman runtime'
sudo loginctl enable-linger "$AGENT_USER"
AGENT_UID=$(id -u "$AGENT_USER")
RUNTIME_DIR=/run/user/$AGENT_UID
[[ -d $RUNTIME_DIR ]] || die "No $RUNTIME_DIR yet; reboot and rerun this script."
agent() { sudo -u "$AGENT_USER" -H env "XDG_RUNTIME_DIR=$RUNTIME_DIR" "$@"; }
# Use bash's permission tests as aiagent. Calling external `test` through the
# env wrapper produced a false negative on one Ubuntu 26.04 setup.
agent_can_access() {
    sudo -u "$AGENT_USER" -H bash -c '
        test -r "$1" && test -w "$1" && test -x "$1"
    ' _ "$1"
}
agent mkdir -p "$AGENT_HOME/.codex" "$AGENT_HOME/.hermes" "$AGENT_HOME/.config/git" "$AGENT_HOME/.local/share/ai-workbench"
agent chmod 700 "$AGENT_HOME/.codex" "$AGENT_HOME/.hermes" "$AGENT_HOME/.config/git"
agent mkdir -p "$AGENT_HOME/.claude" "$AGENT_HOME/.kimi-code" \
    "$AGENT_HOME/.config/opencode" "$AGENT_HOME/.local/share/opencode" "$AGENT_HOME/.cache/opencode"
agent chmod 700 "$AGENT_HOME/.claude" "$AGENT_HOME/.kimi-code" \
    "$AGENT_HOME/.config/opencode" "$AGENT_HOME/.local/share/opencode" "$AGENT_HOME/.cache/opencode"
if ! agent test -e "$AGENT_HOME/.claude.json"; then
    printf '{}\n' | agent tee "$AGENT_HOME/.claude.json" >/dev/null
fi
agent chmod 600 "$AGENT_HOME/.claude.json"
agent touch "$AGENT_HOME/.config/git/config"
agent chmod 600 "$AGENT_HOME/.config/git/config"
# The selected repository belongs to the desktop user; Git otherwise rejects
# it as dubious ownership when invoked by the container's aiagent mapping.
agent git config --file "$AGENT_HOME/.config/git/config" --replace-all safe.directory /workspace

say 'Installing the Codex image definition'
agent tee "$AGENT_HOME/.local/share/ai-workbench/Containerfile" >/dev/null <<'CONTAINERFILE'
FROM docker.io/library/ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git jq less ripgrep openssh-client \
    build-essential python3 python3-pip python3-venv nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @openai/codex \
    && groupadd --gid 20000 agent \
    && useradd --uid 20000 --gid 20000 --create-home --shell /bin/bash agent
USER agent
WORKDIR /workspace
CMD ["/bin/bash"]
CONTAINERFILE

for tool_name in opencode kimi claude; do
    agent mkdir -p "$AGENT_HOME/.local/share/ai-workbench/$tool_name"
done
TOOL_ROOT="$AGENT_HOME/.local/share/ai-workbench/tools"
agent mkdir -p "$TOOL_ROOT/codex" "$TOOL_ROOT/hermes"
GCP_ROOT="$AGENT_HOME/.local/share/ai-workbench/gcp"
agent mkdir -p "$GCP_ROOT/codex" "$GCP_ROOT/hermes" "$GCP_ROOT/contexts"
agent chmod 700 "$GCP_ROOT/contexts"
agent mkdir -p "$AGENT_HOME/.local/share/ai-workbench/cloudflare/contexts"
agent chmod 700 "$AGENT_HOME/.local/share/ai-workbench/cloudflare/contexts"
agent tee "$GCP_ROOT/codex/Containerfile" >/dev/null <<'GCP_CODEX'
ARG BASE_IMAGE=localhost/ai-codex:latest
FROM ${BASE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gnupg curl ca-certificates \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
       | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main' \
       > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
    && rm -rf /var/lib/apt/lists/*
USER agent
GCP_CODEX
agent tee "$GCP_ROOT/hermes/Containerfile" >/dev/null <<'GCP_HERMES'
ARG BASE_IMAGE=docker.io/nousresearch/hermes-agent:latest
FROM ${BASE_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends gnupg curl ca-certificates \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
       | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo 'deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main' \
       > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
    && rm -rf /var/lib/apt/lists/*
GCP_HERMES
# User-owned extensions are initialized once. Rerunning setup preserves edits.
if ! agent bash -c 'test -e "$1"' _ "$TOOL_ROOT/codex/Containerfile"; then
    agent tee "$TOOL_ROOT/codex/Containerfile" >/dev/null <<'CODEX_TOOLS'
FROM localhost/ai-codex:latest
USER root
# Add Ubuntu apt packages here; this layer is optional until `ai tools build`.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano radare2 binwalk \
    && rm -rf /var/lib/apt/lists/*
USER agent
CODEX_TOOLS
fi
if ! agent bash -c 'test -e "$1"' _ "$TOOL_ROOT/hermes/Containerfile"; then
    agent tee "$TOOL_ROOT/hermes/Containerfile" >/dev/null <<'HERMES_TOOLS'
FROM docker.io/nousresearch/hermes-agent:latest
USER root
# Add Debian apt packages here. Keep the official Hermes entrypoint intact.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano binwalk \
    && rm -rf /var/lib/apt/lists/*
HERMES_TOOLS
fi
agent tee "$AGENT_HOME/.local/share/ai-workbench/opencode/Containerfile" >/dev/null <<'OPENCODE'
ARG BASE_IMAGE=localhost/ai-codex:latest
FROM ${BASE_IMAGE}
USER root
RUN npm install -g opencode-ai
USER agent
OPENCODE
agent tee "$AGENT_HOME/.local/share/ai-workbench/kimi/Containerfile" >/dev/null <<'KIMI'
ARG BASE_IMAGE=localhost/ai-codex:latest
FROM ${BASE_IMAGE}
USER root
RUN npm install -g @moonshot-ai/kimi-code
USER agent
KIMI
agent tee "$AGENT_HOME/.local/share/ai-workbench/claude/Containerfile" >/dev/null <<'CLAUDE'
ARG BASE_IMAGE=localhost/ai-codex:latest
FROM ${BASE_IMAGE}
USER root
RUN npm install -g @anthropic-ai/claude-code
USER agent
CLAUDE

say 'Building Codex and pulling Hermes'
if (( FINISH_ONLY )); then
    agent podman image exists localhost/ai-codex:latest || die 'Codex image missing; rerun without --finish.'
    agent podman image exists docker.io/nousresearch/hermes-agent:latest || die 'Hermes image missing; rerun without --finish.'
else
    agent podman build --pull -t localhost/ai-codex:latest "$AGENT_HOME/.local/share/ai-workbench"
    agent podman pull docker.io/nousresearch/hermes-agent:latest
fi

say 'Installing the launcher'
LAUNCHER=/usr/local/bin/ai
if [[ -e $LAUNCHER ]] && ! grep -Fxq "$MARKER" "$LAUNCHER"; then
    die "$LAUNCHER already exists and is not managed by this script."
fi
sudo tee "$LAUNCHER" >/dev/null <<'LAUNCHER'
#!/usr/bin/env bash
# Managed by setup-ai-workbench.sh
set -Eeuo pipefail
AGENT_USER=aiagent
AGENT_HOME=/home/aiagent
TOOL_ROOT=$AGENT_HOME/.local/share/ai-workbench/tools
GCP_ROOT=$AGENT_HOME/.local/share/ai-workbench/gcp
CF_ROOT=$AGENT_HOME/.local/share/ai-workbench/cloudflare
LOGIN_HOME=$(getent passwd "$(id -un)" | cut -d: -f6)
PROJECTS=$LOGIN_HOME/projects
RUNTIME_DIR=/run/user/$(id -u "$AGENT_USER")
agent() { sudo -u "$AGENT_USER" -H env "XDG_RUNTIME_DIR=$RUNTIME_DIR" "$@"; }
agent_can_access() {
    sudo -u "$AGENT_USER" -H bash -c '
        test -r "$1" && test -w "$1" && test -x "$1"
    ' _ "$1"
}
usage() {
    printf 'Usage: ai {shell|codex|hermes|opencode|kimi|claude} [arguments...]\n'
    printf '       ai install {opencode|kimi|claude}   # optional tool image\n'
    printf '       ai {status|pull|login}            # login is for Codex\n'
    printf '       ai tools {paths|edit codex|edit hermes|build}\n'
    printf '       ai gcp {install|use "PROJECT NAME OR ID"|refresh|status|clear}\n'
    printf '       ai cloudflare {use|status|clear}  # use prompts for a dashboard API token\n'
    printf '       ai git-identity "Name" "email@example.com"\n'
}
optional_image() { printf 'localhost/ai-%s:latest' "$1"; }
codex_tools_base() {
    if agent podman image exists localhost/ai-codex-tools:latest; then
        printf 'localhost/ai-codex-tools:latest'
    else
        printf 'localhost/ai-codex:latest'
    fi
}
hermes_tools_base() {
    if agent podman image exists localhost/ai-hermes-tools:latest; then
        printf 'localhost/ai-hermes-tools:latest'
    else
        printf 'docker.io/nousresearch/hermes-agent:latest'
    fi
}
codex_base() {
    if agent podman image exists localhost/ai-codex-gcp:latest; then
        printf 'localhost/ai-codex-gcp:latest'
    else
        codex_tools_base
    fi
}
hermes_base() {
    if agent podman image exists localhost/ai-hermes-gcp:latest; then
        printf 'localhost/ai-hermes-gcp:latest'
    else
        hermes_tools_base
    fi
}
build_gcp() {
    agent podman build --pull=never --build-arg "BASE_IMAGE=$(codex_tools_base)" \
        -t localhost/ai-codex-gcp:latest "$GCP_ROOT/codex"
    agent podman build --pull=never --build-arg "BASE_IMAGE=$(hermes_tools_base)" \
        -t localhost/ai-hermes-gcp:latest "$GCP_ROOT/hermes"
}
install_optional() {
    local tool_name=$1
    agent podman build --pull=never --build-arg "BASE_IMAGE=$(codex_base)" \
        -t "$(optional_image "$tool_name")" \
        "$AGENT_HOME/.local/share/ai-workbench/$tool_name"
    agent podman run --rm --userns=keep-id:uid=20000,gid=20000 --user=20000:20000 \
        "$(optional_image "$tool_name")" "$tool_name" --version
}
build_tools() {
    agent podman build --pull=never -t localhost/ai-codex-tools:latest "$TOOL_ROOT/codex"
    agent podman build --pull=never -t localhost/ai-hermes-tools:latest "$TOOL_ROOT/hermes"
    if agent podman image exists localhost/ai-codex-gcp:latest; then
        build_gcp
    fi
    for tool_name in opencode kimi claude; do
        if agent podman image exists "$(optional_image "$tool_name")"; then
            install_optional "$tool_name"
        fi
    done
}
case ${1:-shell} in
    help|-h|--help) usage; exit 0 ;;
    status)
        printf 'codex, hermes: installed by setup\n'
        for tool_name in opencode kimi claude; do
            if agent podman image exists "$(optional_image "$tool_name")"; then
                printf '%s: installed\n' "$tool_name"
            else
                printf '%s: available (ai install %s)\n' "$tool_name" "$tool_name"
            fi
        done
        exit 0 ;;
    install)
        [[ $# == 2 ]] || { usage >&2; exit 2; }
        case $2 in opencode|kimi|claude) install_optional "$2" ;; *) usage >&2; exit 2 ;; esac
        exit 0 ;;
    cloudflare)
        [[ $# == 2 ]] || { usage >&2; exit 2; }
        case $2 in use|status|clear) command_name=cloudflare ;; *) usage >&2; exit 2 ;; esac ;;
    gcp)
        if [[ ${2:-} == install ]]; then
            [[ $# == 2 ]] || { usage >&2; exit 2; }
            build_gcp
            for tool_name in opencode kimi claude; do
                if agent podman image exists "$(optional_image "$tool_name")"; then
                    install_optional "$tool_name"
                fi
            done
            printf 'gcloud installed in the agent images. In a project, run: ai gcp use "PROJECT NAME OR ID"\n'
            exit 0
        fi
        case ${2:-} in use|refresh|status|clear) command_name=gcp ;; *) usage >&2; exit 2 ;; esac ;;
    tools)
        case ${2:-paths} in
            paths)
                [[ $# -le 2 ]] || { usage >&2; exit 2; }
                printf 'Codex/OpenCode/Kimi/Claude: %s\n' "$TOOL_ROOT/codex/Containerfile"
                printf 'Hermes: %s\n' "$TOOL_ROOT/hermes/Containerfile" ;;
            edit)
                [[ $# == 3 ]] || { usage >&2; exit 2; }
                case $3 in codex|hermes) ;; *) usage >&2; exit 2 ;; esac
                exec sudoedit -u "$AGENT_USER" "$TOOL_ROOT/$3/Containerfile" ;;
            build)
                [[ $# == 2 ]] || { usage >&2; exit 2; }
                build_tools ;;
            *) usage >&2; exit 2 ;;
        esac
        exit 0 ;;
    pull)
        agent podman build --pull -t localhost/ai-codex:latest "$AGENT_HOME/.local/share/ai-workbench"
        agent podman pull docker.io/nousresearch/hermes-agent:latest
        if agent podman image exists localhost/ai-codex-tools:latest || \
           agent podman image exists localhost/ai-hermes-tools:latest; then
            build_tools
            exit 0
        fi
        if agent podman image exists localhost/ai-codex-gcp:latest; then
            build_gcp
        fi
        for tool_name in opencode kimi claude; do
            if agent podman image exists "$(optional_image "$tool_name")"; then
                install_optional "$tool_name"
            fi
        done
        exit 0 ;;
    git-identity)
        [[ $# == 3 ]] || { usage >&2; exit 2; }
        agent git config --file "$AGENT_HOME/.config/git/config" user.name "$2"
        agent git config --file "$AGENT_HOME/.config/git/config" user.email "$3"
        exit 0 ;;
    login)
        shift
        exec sudo -u "$AGENT_USER" -H env "XDG_RUNTIME_DIR=$RUNTIME_DIR" \
            podman run --rm -it --security-opt=no-new-privileges --cap-drop=ALL \
            --userns=keep-id:uid=20000,gid=20000 --user=20000:20000 \
            --volume "$AGENT_HOME/.codex:/home/agent/.codex:rw" \
            --tmpfs /workspace:rw,nosuid,nodev \
            --workdir /workspace localhost/ai-codex:latest codex login --device-auth "$@" ;;
    shell|codex|hermes|opencode|kimi|claude|claude-code|cc)
        command_name=${1:-shell}; shift || true
        case $command_name in claude-code|cc) command_name=claude ;; esac ;;
    *) usage >&2; exit 2 ;;
esac

# Mount a whole Git repository when invoked in a subdirectory. Otherwise mount
# only the current directory. Refuse ~/projects itself to avoid broad exposure.
ROOT=$(realpath -e -- "$PROJECTS")
HERE=$(realpath -e -- "$PWD")
case "$HERE/" in "$ROOT/"*) ;; *) printf 'Outside %s\n' "$ROOT" >&2; exit 1;; esac
[[ $HERE != "$ROOT" ]] || { printf 'Choose one project inside %s\n' "$ROOT" >&2; exit 1; }
if git -C "$HERE" rev-parse --is-inside-work-tree 2>/dev/null | grep -qx true; then
    WORKSPACE=$(realpath -e -- "$(git -C "$HERE" rev-parse --show-toplevel)")
else
    WORKSPACE=$HERE
fi
case "$WORKSPACE/" in "$ROOT/"*) ;; *) printf 'Repository is outside %s\n' "$ROOT" >&2; exit 1;; esac
[[ $WORKSPACE != "$ROOT" ]] || { printf 'Choose a repository inside %s\n' "$ROOT" >&2; exit 1; }
[[ -d $WORKSPACE/.git || ! -e $WORKSPACE/.git ]] || { printf 'Git worktrees with external .git metadata need a separate setup.\n' >&2; exit 1; }
if ! agent_can_access "$WORKSPACE"; then
    printf 'aiagent cannot read, write, and traverse %s. Check the path ACLs.\n' "$WORKSPACE" >&2
    exit 1
fi

# Contexts live outside repositories. A container sees only its own context.
CONTEXT_HASH=$(printf '%s' "$WORKSPACE" | sha256sum | cut -d' ' -f1)
CF_CONTEXT="$CF_ROOT/contexts/$CONTEXT_HASH"
if [[ $command_name == cloudflare ]]; then
    case $2 in
        use)
            # Credentials never appear in command arguments, shell history, or
            # repository files. Cloudflare enforces the token's dashboard TTL.
            read -r -p 'Cloudflare account ID: ' CF_ACCOUNT </dev/tty
            [[ $CF_ACCOUNT =~ ^[[:xdigit:]]{32}$ ]] || { printf 'Account ID must be 32 hexadecimal characters.\n' >&2; exit 2; }
            read -r -p 'Cloudflare zone ID (optional): ' CF_ZONE </dev/tty
            [[ -z $CF_ZONE || $CF_ZONE =~ ^[[:xdigit:]]{32}$ ]] || { printf 'Zone ID must be 32 hexadecimal characters.\n' >&2; exit 2; }
            read -r -s -p 'Cloudflare API token (hidden): ' CF_TOKEN </dev/tty
            printf '\n' >/dev/tty
            [[ $CF_TOKEN =~ ^[a-zA-Z0-9_-]+$ ]] || { printf 'Invalid API token format.\n' >&2; exit 2; }
            {
                printf 'CLOUDFLARE_API_TOKEN=%s\nCLOUDFLARE_ACCOUNT_ID=%s\n' "$CF_TOKEN" "$CF_ACCOUNT"
                [[ -z $CF_ZONE ]] || printf 'CLOUDFLARE_ZONE_ID=%s\n' "$CF_ZONE"
                true
            } | agent bash -c '
                set -e; umask 077; mkdir -p -- "$1"
                temp=$(mktemp "$1/.env.XXXXXX")
                trap '\''rm -f -- "$temp"'\'' EXIT
                cat > "$temp"
                mv -f -- "$temp" "$1/env"
            ' _ "$CF_CONTEXT"
            unset CF_TOKEN
            printf 'Cloudflare token stored for %s. Start or restart its containers to load it. Permissions and expiry are controlled by Cloudflare.\n' "$WORKSPACE" ;;
        status)
            agent test -s "$CF_CONTEXT/env" || { printf 'No Cloudflare token configured here. Run: ai cloudflare use\n'; exit 0; }
            agent bash -c '
                while IFS= read -r line; do
                    case $line in CLOUDFLARE_ACCOUNT_ID=*|CLOUDFLARE_ZONE_ID=*) printf "%s\n" "$line" ;; esac
                done < "$1"
            ' _ "$CF_CONTEXT/env"
            printf 'Token configured; validity, permissions, and expiry must be checked in Cloudflare.\n' ;;
        clear)
            agent rm -rf -- "$CF_CONTEXT"
            printf 'Local Cloudflare authorization removed. Revoke the token in Cloudflare and stop running containers to remove their existing copies.\n' ;;
    esac
    exit 0
fi

GCP_CONTEXT="$GCP_ROOT/contexts/$CONTEXT_HASH"
gcp_identity() {
    agent test -f "$GCP_CONTEXT/context" || { printf 'No GCP context here. Run: ai gcp use "PROJECT NAME OR ID"\n' >&2; exit 1; }
    mapfile -t gcp_lines < <(agent cat "$GCP_CONTEXT/context")
    [[ ${#gcp_lines[@]} == 2 || ${#gcp_lines[@]} == 3 ]] || { printf 'Invalid GCP context. Run ai gcp use again.\n' >&2; exit 1; }
    GCP_PROJECT=${gcp_lines[0]}
    GCP_SERVICE_ACCOUNT=${gcp_lines[1]}
    GCP_TOKEN_LIFETIME=${gcp_lines[2]:-unknown}
}
gcp_write_context() {
    printf '%s\n%s\n%s\n' "$GCP_PROJECT" "$GCP_SERVICE_ACCOUNT" "$GCP_TOKEN_LIFETIME" \
        | agent bash -c '
            set -e; umask 077
            temp=$(mktemp "$1/.context.XXXXXX")
            trap '\''rm -f -- "$temp"'\'' EXIT
            cat > "$temp"
            mv -f -- "$temp" "$1/context"
        ' _ "$GCP_CONTEXT"
}
gcp_resolve_project() {
    command -v gcloud >/dev/null || { printf 'Install and log in to gcloud on your desktop first.\n' >&2; exit 1; }
    command -v python3 >/dev/null || { printf 'Python 3 is needed on the desktop to resolve project names.\n' >&2; exit 1; }
    # Match the project ID or display name exactly. Never guess if names repeat.
    gcloud projects list --format=json | python3 -c '
import json, sys
projects = json.load(sys.stdin)
query = sys.argv[1]
ids = [p["projectId"] for p in projects if p.get("projectId") == query]
matches = ids or [p["projectId"] for p in projects if p.get("name") == query]
if len(matches) != 1:
    print("Project not found or name is ambiguous. Matching IDs: " +
          (", ".join(matches) if matches else "none"), file=sys.stderr)
    sys.exit(1)
print(matches[0])
' "$1"
}
gcp_prepare_service_account() {
    local caller display created=0 delay role old_roles
    caller=$(gcloud config get-value account)
    [[ $caller =~ ^[^[:space:]@]+@[^[:space:]@]+$ ]] || {
        printf 'No desktop gcloud user account selected; run gcloud auth login.\n' >&2; return 1;
    }
    gcloud services enable iamcredentials.googleapis.com --project="$GCP_PROJECT" >/dev/null
    if display=$(gcloud iam service-accounts describe "$GCP_SERVICE_ACCOUNT" \
        --project="$GCP_PROJECT" --format='value(displayName)' 2>/dev/null); then
        [[ $display == 'AI workbench (project containers)' ]] || {
            printf '%s already exists and is not managed by ai gcp use. Choose a different service account manually.\n' \
                "$GCP_SERVICE_ACCOUNT" >&2; return 1;
        }
    else
        gcloud iam service-accounts create ai-workbench \
            --display-name='AI workbench (project containers)' \
            --project="$GCP_PROJECT" >/dev/null
        created=1
    fi
    # IAM can take a minute to expose a newly created service account.
    for delay in 0 2 4 8 16 32; do
        (( delay == 0 )) || sleep "$delay"
        if gcloud iam service-accounts add-iam-policy-binding "$GCP_SERVICE_ACCOUNT" \
            --project="$GCP_PROJECT" --member="user:$caller" \
            --role=roles/iam.serviceAccountTokenCreator --quiet >/dev/null; then
            break
        fi
        (( created && delay < 32 )) || return 1
    done
    gcloud projects add-iam-policy-binding "$GCP_PROJECT" \
        --member="serviceAccount:$GCP_SERVICE_ACCOUNT" \
        --role=roles/admin --quiet >/dev/null
    # Migrate the grants from previous workbench versions after Admin succeeds.
    old_roles=$(gcloud projects get-iam-policy "$GCP_PROJECT" --format=json | python3 -c '
import json, sys
policy = json.load(sys.stdin)
member = sys.argv[1]
previous = {
    "roles/viewer", "roles/editor", "roles/iap.admin",
    "roles/appengine.appAdmin", "roles/compute.admin",
    "roles/iam.serviceAccountUser", "roles/iam.serviceAccountAdmin",
    "roles/cloudbuild.builds.editor", "roles/storage.objectAdmin",
    "roles/serviceusage.serviceUsageAdmin",
    "roles/resourcemanager.projectIamAdmin",
}
for binding in policy.get("bindings", []):
    if (binding.get("role") in previous and
            member in binding.get("members", []) and
            not binding.get("condition")):
        print(binding["role"])
' "serviceAccount:$GCP_SERVICE_ACCOUNT")
    while IFS= read -r role; do
        [[ -n $role ]] || continue
        gcloud projects remove-iam-policy-binding "$GCP_PROJECT" \
            --member="serviceAccount:$GCP_SERVICE_ACCOUNT" \
            --role="$role" --quiet >/dev/null
    done <<< "$old_roles"
    # A project owner may be unable to change organization policy. In that
    # case the token mint step below tries 12 hours, then falls back to one.
    gcloud resource-manager org-policies allow \
        constraints/iam.allowServiceAccountCredentialLifetimeExtension \
        "$GCP_SERVICE_ACCOUNT" --project="$GCP_PROJECT" --quiet >/dev/null 2>&1 || true
}
gcp_mint_for_seconds() {
    # The token travels through a pipe, never a command argument or a project file.
    gcloud auth print-access-token --impersonate-service-account="$GCP_SERVICE_ACCOUNT" \
        --lifetime="$1" \
        | agent bash -c '
            set -e; umask 077; mkdir -p -- "$1"
            temp=$(mktemp "$1/.token.XXXXXX")
            trap '\''rm -f -- "$temp"'\'' EXIT
            cat > "$temp"; test -s "$temp"
            mv -f -- "$temp" "$1/token"
        ' _ "$GCP_CONTEXT"
}
gcp_mint_one_hour_with_retry() {
    local delay errors
    errors=$(mktemp)
    # Policy writes can succeed minutes before getAccessToken sees the grant.
    # Retry only that denial, and only after this invocation prepared IAM.
    for delay in 0 10 20 40 60 60 60 60 60 60; do
        if (( delay )); then
            printf 'Waiting %s seconds for the impersonation grant to propagate...\n' "$delay" >&2
            sleep "$delay"
        fi
        if gcp_mint_for_seconds 3600 2>"$errors"; then
            rm -f -- "$errors"
            return 0
        fi
        if [[ ${GCP_WAIT_FOR_IAM:-0} != 1 ]] || \
           ! grep -q 'PERMISSION_DENIED' "$errors" || \
           ! grep -q 'iam.serviceAccounts.getAccessToken' "$errors"; then
            break
        fi
    done
    cat "$errors" >&2
    rm -f -- "$errors"
    return 1
}
gcp_mint() {
    command -v gcloud >/dev/null || { printf 'Install and log in to gcloud on your desktop first.\n' >&2; exit 1; }
    if gcp_mint_for_seconds 43200 2>/dev/null; then
        GCP_TOKEN_LIFETIME=43200
    elif gcp_mint_one_hour_with_retry; then
        # The first extended-lifetime attempt may have failed only because of
        # IAM propagation. Try it again once the one-hour mint succeeds.
        if gcp_mint_for_seconds 43200 2>/dev/null; then
            GCP_TOKEN_LIFETIME=43200
            return 0
        fi
        GCP_TOKEN_LIFETIME=3600
        printf '12-hour token unavailable. Using a one-hour token. An Organization Policy Administrator can allow %s under constraints/iam.allowServiceAccountCredentialLifetimeExtension for project %s.\n' \
            "$GCP_SERVICE_ACCOUNT" "$GCP_PROJECT" >&2
    else
        printf 'Could not mint a service account token. Check gcloud login and impersonation permissions.\n' >&2
        return 1
    fi
}
if [[ $command_name == gcp ]]; then
    case $2 in
        use)
            [[ $# == 3 ]] || { usage >&2; exit 2; }
            GCP_PROJECT=$(gcp_resolve_project "$3")
            [[ $GCP_PROJECT =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || { printf 'Unsupported project ID.\n' >&2; exit 2; }
            GCP_SERVICE_ACCOUNT="ai-workbench@$GCP_PROJECT.iam.gserviceaccount.com"
            gcp_prepare_service_account
            GCP_WAIT_FOR_IAM=1
            gcp_mint
            gcp_write_context
            printf 'GCP context: %s via %s. Token lifetime: %s seconds; run ai gcp refresh before it expires.\n' \
                "$GCP_PROJECT" "$GCP_SERVICE_ACCOUNT" "$GCP_TOKEN_LIFETIME" ;;
        refresh)
            [[ $# == 2 ]] || { usage >&2; exit 2; }
            gcp_identity; gcp_mint
            gcp_write_context
            printf 'Refreshed token for %s via %s (%s seconds).\n' "$GCP_PROJECT" "$GCP_SERVICE_ACCOUNT" "$GCP_TOKEN_LIFETIME" ;;
        status)
            [[ $# == 2 ]] || { usage >&2; exit 2; }
            gcp_identity
            printf 'Project: %s\nService account: %s\nToken lifetime: %s seconds\n' \
                "$GCP_PROJECT" "$GCP_SERVICE_ACCOUNT" "$GCP_TOKEN_LIFETIME"
            agent stat -c 'Token last refreshed: %y' "$GCP_CONTEXT/token" ;;
        clear)
            [[ $# == 2 ]] || { usage >&2; exit 2; }
            agent rm -rf -- "$GCP_CONTEXT"
            printf 'GCP context removed for %s.\n' "$WORKSPACE" ;;
    esac
    exit 0
fi

gcp_args=()
if agent test -s "$GCP_CONTEXT/token"; then
    gcp_identity
    if ! agent podman image exists localhost/ai-codex-gcp:latest || \
       ! agent podman image exists localhost/ai-hermes-gcp:latest; then
        printf 'GCP context exists, but gcloud images are missing. Run: ai gcp install\n' >&2
        exit 1
    fi
    gcp_args=(--volume "$GCP_CONTEXT:/run/ai-gcp:ro"
        --env "CLOUDSDK_CORE_PROJECT=$GCP_PROJECT"
        --env "GOOGLE_CLOUD_PROJECT=$GCP_PROJECT"
        --env CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=/run/ai-gcp/token
        --env CLOUDSDK_CONFIG=/tmp/ai-gcloud-config)
fi

common=(--rm -it --pids-limit=1024 --memory=8g --cpus=4
    --volume "$WORKSPACE:/workspace:rw" --workdir /workspace "${gcp_args[@]}")
if agent test -s "$CF_CONTEXT/env"; then
    common+=(--env-file "$CF_CONTEXT/env")
fi
case "$command_name" in
    shell|codex|opencode|kimi|claude)
        args=(--security-opt=no-new-privileges --cap-drop=ALL
            --userns=keep-id:uid=20000,gid=20000 --user=20000:20000
            --volume "$AGENT_HOME/.config/git:/home/agent/.config/git:ro"
            --env GIT_CONFIG_GLOBAL=/home/agent/.config/git/config)
        case "$command_name" in
            shell)
                image=$(codex_base)
                command_name=/bin/bash ;;
            codex)
                image=$(codex_base)
                args+=(--volume "$AGENT_HOME/.codex:/home/agent/.codex:rw") ;;
            opencode)
                image=$(optional_image opencode)
                args+=(--volume "$AGENT_HOME/.config/opencode:/home/agent/.config/opencode:rw"
                    --volume "$AGENT_HOME/.local/share/opencode:/home/agent/.local/share/opencode:rw"
                    --volume "$AGENT_HOME/.cache/opencode:/home/agent/.cache/opencode:rw") ;;
            kimi)
                image=$(optional_image kimi)
                args+=(--volume "$AGENT_HOME/.kimi-code:/home/agent/.kimi-code:rw") ;;
            claude)
                image=$(optional_image claude)
                args+=(--volume "$AGENT_HOME/.claude:/home/agent/.claude:rw"
                    --volume "$AGENT_HOME/.claude.json:/home/agent/.claude.json:rw") ;;
        esac
        if ! agent podman image exists "$image"; then
            printf '%s is not installed. Run: ai install %s\n' "$command_name" "$command_name" >&2
            exit 1
        fi
        exec sudo -u "$AGENT_USER" -H env "XDG_RUNTIME_DIR=$RUNTIME_DIR" \
            podman run "${common[@]}" "${args[@]}" "$image" "$command_name" "$@" ;;
    hermes)
        # Hermes' official entrypoint needs namespace-local root for s6 startup.
        # It then drops services to UID 10000, mapped to the host aiagent UID.
        exec sudo -u "$AGENT_USER" -H env "XDG_RUNTIME_DIR=$RUNTIME_DIR" \
            podman run "${common[@]}" \
                --userns=keep-id:uid=10000,gid=10000 --user=0:0 \
                --env HERMES_UID=10000 --env HERMES_GID=10000 \
                --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory \
                --env GIT_CONFIG_VALUE_0=/workspace \
                --volume "$AGENT_HOME/.hermes:/opt/data:rw" \
                "$(hermes_base)" "$@" ;;
esac
LAUNCHER
sudo chmod 0755 "$LAUNCHER"

say 'Configuring one-way passwordless switch to aiagent'
SUDOERS=/etc/sudoers.d/90-ai-workbench
if sudo test -e "$SUDOERS" && ! sudo grep -Fxq "$MARKER" "$SUDOERS"; then
    die "$SUDOERS already exists and is not managed by this script."
fi
printf '%s\n%s ALL=(%s) NOPASSWD: ALL\n' "$MARKER" "$LOGIN_USER" "$AGENT_USER" | sudo tee "$SUDOERS" >/dev/null
sudo chmod 0440 "$SUDOERS"
sudo visudo -cf "$SUDOERS"

say 'Checking rootless image and project access'
agent podman info --format '{{.Host.Security.Rootless}}' | grep -qx true || die 'Podman did not run rootless.'
if ! agent_can_access "$PROJECTS"; then
    printf 'Project ACL validation failed. Expected: home traverse; projects read/write/traverse.\n' >&2
    sudo -u "$AGENT_USER" -H bash -c '
        for path in "$1" "$2"; do
            printf "%s:" "$path"
            for mode in r w x; do
                if test "-$mode" "$path"; then printf " %s=yes" "$mode"; else printf " %s=no" "$mode"; fi
            done
            printf "\n"
        done
    ' _ "$LOGIN_HOME" "$PROJECTS" >&2
    getfacl -e "$LOGIN_HOME" "$PROJECTS" >&2
    namei -l "$PROJECTS" >&2
    die 'Check the first denied path or its ACL mask shown above.'
fi
agent podman run --rm --userns=keep-id:uid=20000,gid=20000 --user=20000:20000 \
    localhost/ai-codex:latest codex --version
agent podman run --rm --userns=keep-id:uid=10000,gid=10000 --user=0:0 \
    --env HERMES_UID=10000 --env HERMES_GID=10000 \
    --volume "$AGENT_HOME/.hermes:/opt/data:rw" \
    docker.io/nousresearch/hermes-agent:latest version
printf '\nReady. Try: cd %q/your-repo && ai codex\n' "$PROJECTS"
printf 'Codex sign-in: ai login   Hermes setup: cd %q/your-repo && ai hermes setup\n' "$PROJECTS"
printf 'Optional tools: ai install opencode | kimi | claude; then ai opencode | kimi | claude\n'
printf 'Tool availability: ai status\n'
printf 'Add packages: ai tools edit codex; ai tools edit hermes; ai tools build\n'
printf 'Set commit identity: ai git-identity "Your Name" "you@example.com"\n'
printf 'Google Cloud CLI: ai gcp install; then, in a project: ai gcp use "PROJECT NAME OR ID"\n'
printf 'Cloudflare: create an expiring API token in the dashboard; then, in a project: ai cloudflare use\n'
