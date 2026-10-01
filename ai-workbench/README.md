# AI Workbench

Run coding agents in rootless Podman containers under a dedicated, unprivileged host account. Work on one repository at a time, keep agent state outside your desktop home, and optionally authorize that repository to use Google Cloud and Cloudflare.

The setup supports Codex, Hermes, OpenCode, Kimi Code, and Claude Code. Codex and Hermes are installed during setup; the other agents are optional.

NOTE: This tool keeps coding harnesses/agents from arbitrary file access outside of a project and improves safety with time- and/or project-bound credentials, but it does NOT separate multiple accounts from the same AI provider (e.g. work/personal).

## Requirements

- Ubuntu **26.04**, with systemd and a normal desktop login. The script rejects other distributions and releases.
- A login account with `sudo` access for installation.
- Internet access for operating system packages, container images, and agent packages.
- Projects stored beneath `~/projects`.
- Agent subscriptions or API credentials, configured separately for each agent.
- For GCP authorization: Python 3 and a current `gcloud` CLI installed and authenticated on the host.

Review [setup-ai-workbench.sh](setup-ai-workbench.sh) before running it. It modifies host accounts, ACLs, sudoers, and the rootless container runtime. GCP authorization also makes cloud IAM changes.

## Install

Run the script as your normal login user, without putting `sudo` before it:

```bash
bash setup-ai-workbench.sh
```

The script detects your login name and home directory. It:

1. Installs Podman and its supporting packages.
2. Creates the `aiagent` host account if necessary.
3. Grants `aiagent` traversal of your home directory and read/write access to `~/projects` through ACLs.
4. Enables lingering for the `aiagent` user runtime.
5. Builds the Codex image and pulls the Hermes image.
6. Installs `/usr/local/bin/ai`.
7. Allows your login user to run commands as `aiagent` without a password.
8. Checks rootless Podman, project permissions, and agent versions.

The sudoers rule is one-way: your desktop user can become `aiagent`; it does not grant `aiagent` permission to become your desktop user or root.

If setup stops partway through, address the reported error and rerun it. Existing agent state and custom tool Containerfiles are preserved. Completed host changes are not rolled back automatically.

Once the base images exist, use this to update the launcher and generated definitions without reinstalling host packages or rebuilding the base images:

```bash
bash setup-ai-workbench.sh --finish
```

`--finish` still performs account, ACL, runtime, sudoers, and validation steps. It is not a first-time installation mode.

## Start working

```bash
mkdir -p ~/projects/my-project
cd ~/projects/my-project

ai login                 # Codex device authentication
ai codex
```

Other entry points:

```bash
ai shell                 # Bash in the Codex-based image
ai hermes setup          # Initial Hermes configuration
ai hermes

ai install opencode
ai install kimi
ai install claude

ai opencode
ai kimi
ai claude
```

`ai claude-code` and `ai cc` are aliases for `ai claude`. Agent arguments are forwarded, for example `ai codex --help`. `ai` without arguments starts the container shell.

Configure OpenCode, Kimi, and Claude authentication using their own CLI flows after starting them. `ai login` authenticates Codex only.

The current project appears as `/workspace` inside the container. If you start from a Git repository's subdirectory, the launcher mounts the whole repository and starts at its root. For a non-Git directory, it mounts only the current directory.

The launcher refuses `~/projects` itself, paths outside that tree, and Git worktrees whose `.git` is a file pointing to external metadata.

Set the shared container Git commit identity with:

```bash
ai git-identity "Your Name" "you@example.com"
```

This sets commit metadata. It does not configure Git hosting authentication or forward your desktop SSH keys.

## Add tools to the images

Host-installed programs are not automatically available inside containers. Install tools and their dependencies into the images:

```bash
ai tools paths
ai tools edit codex
ai tools edit hermes
ai tools build
```

The initial Codex tool layer includes `nano`, `radare2`, and `binwalk`; the initial Hermes layer includes `nano` and `binwalk`. These layers are optional until you run `ai tools build`. Package availability depends on the image's distribution repositories; edit the definitions if a listed package is unavailable.

For the Codex layer, use the following pattern:

```dockerfile
FROM localhost/ai-codex:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    nano unzip file \
    && rm -rf /var/lib/apt/lists/*
USER agent
```

The Hermes layer uses the official Hermes image as its base and retains its entrypoint. Its package repositories can differ from Ubuntu's.

The Codex tool layer is also used as the base for OpenCode, Kimi, and Claude. Building tools rebuilds installed optional agents and the GCP image layers when present. Restart containers to use rebuilt images.

For software such as Ghidra or binwalk-ng, add its required runtime and installation steps to the relevant Containerfile. A snap installed on the host is not a container installation. GUI applications also need display integration, which this launcher does not configure.

Custom tool Containerfiles are initialized once and preserved across setup reruns. The generated base, optional-agent, and GCP definitions are rewritten by setup.

## Google Cloud authorization

GCP authorization uses your **host** `gcloud` login to mint an impersonated service account access token. Your desktop `gcloud` configuration and service account JSON keys are not mounted into containers.

On the host, install and authenticate `gcloud` first:

```bash
gcloud auth login
```

Install `gcloud` into the agent images once:

```bash
ai gcp install
```

Then authorize a repository from your host shell:

```bash
cd ~/projects/my-project
ai gcp use "My GCP Project"
ai gcp status
ai codex
```

`use` accepts an exact project display name or project ID. Display names must identify exactly one visible project; use its ID if the name is ambiguous.

The command:

1. Enables the Service Account Credentials API.
2. Creates or reuses `ai-workbench@PROJECT_ID.iam.gserviceaccount.com`.
3. Grants the selected desktop `gcloud` account Service Account Token Creator on that service account.
4. Grants the service account **project Admin (`roles/admin`)**.
5. Removes the older workbench Viewer/Editor and service-specific grants after Admin succeeds.
6. Attempts to allow extended token lifetime for that service account through the project organization policy.
7. Mints and stores an access token outside the repository.

The service account must have the display name `AI workbench (project containers)` if it already exists. The script refuses to reuse an account with a different display name. Your desktop account needs permission to make these API and IAM changes. Partial cloud changes remain in place if a later step fails; rerunning reapplies the intended configuration.

**Project Admin is intentionally broad.** The agent can manage resources and change project IAM. It does not bypass deny policies, organization constraints, or permissions required on resources outside the selected project. Google currently documents the newer Admin basic role as Preview; consult its [roles overview](https://docs.cloud.google.com/iam/docs/roles-overview) for current status and limitations.

### Token lifetime and renewal

The launcher requests **12 hours**. Google requires the service account to be allowed under `constraints/iam.allowServiceAccountCredentialLifetimeExtension` for lifetimes above one hour. If the exception cannot be used, the launcher falls back to **one hour** and reports the issued lifetime.

After preparing IAM, `use` retries `iam.serviceAccounts.getAccessToken` permission denials for about seven minutes of scheduled waiting. IAM propagation can take longer. Other errors fail without that retry loop.

Renew from the host shell while inside the same repository:

```bash
ai gcp refresh
ai gcp status
```

An existing container reads the refreshed token file on subsequent CLI requests. Start a new container if you change the selected GCP project, since its project defaults were set at launch. Renewal is manual; there is no background broker.

Inside the container:

```bash
gcloud config get-value project
gcloud firestore databases list
```

The launcher supplies:

| Setting | Container value |
| --- | --- |
| `CLOUDSDK_CORE_PROJECT` | Selected project ID |
| `GOOGLE_CLOUD_PROJECT` | Selected project ID |
| `CLOUDSDK_AUTH_ACCESS_TOKEN_FILE` | `/run/ai-gcp/token` |
| `CLOUDSDK_CONFIG` | `/tmp/ai-gcloud-config` |

This authenticates the **gcloud CLI**. It does not configure Application Default Credentials for Google client libraries or Terraform. Project defaults select the target; IAM determines access. An error showing `[None]` can occur with access-token-file authentication because no active account is stored in the container's gcloud configuration.

Remove the local context with:

```bash
ai gcp clear
```

This does not delete the cloud service account, undo IAM or organization policy changes, or revoke an already issued token. Stop containers that should no longer have cloud access. Issued tokens can remain valid until expiry.

## Cloudflare authorization

Create an expiring API token in the [Cloudflare dashboard](https://dash.cloudflare.com/). Select the zone, account, product, and individual resource permissions needed by the project. Set its expiration explicitly; the launcher does not impose a lifetime on imported tokens.

Zone permissions cover services such as DNS, WAF, cache settings, and Worker routes. Workers, Access, and storage/serverless products may require account or product permissions. Use resource restrictions where supported. An account ID or zone ID supplied to the launcher is a default, not an access restriction.

Import the token from the host shell:

```bash
cd ~/projects/my-project
ai cloudflare use
```

The command prompts for:

1. A Cloudflare account ID: 32 hexadecimal characters.
2. An optional zone ID: 32 hexadecimal characters.
3. An API token, entered without echoing it to the terminal.

The token is stored outside the repository in an owner-only environment file. New containers for the project receive `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and the optional `CLOUDFLARE_ZONE_ID`. These variables are available to agents and their subprocesses. Wrangler supports the token and account ID variables.

```bash
ai cloudflare status      # Shows IDs, never the token
ai cloudflare use         # Replace an expired or rotated token
ai cloudflare clear       # Remove the local environment file
```

Restart containers after replacing a Cloudflare token. Clearing the local file does not revoke it or remove its environment variables from running containers. Revoke the token in Cloudflare and stop those containers when removing access.

The launcher does not verify token validity, permissions, or expiry. It does not install Wrangler, create tokens, or store a master provisioning credential. Install Wrangler through your project's dependencies or custom image layer if needed.

## Persistent state and credentials

Agent state is shared across repositories for each agent. Cloud contexts are selected per repository path.

| Host location | Purpose |
| --- | --- |
| `/home/aiagent/.codex` | Codex configuration and authentication |
| `/home/aiagent/.hermes` | Hermes persistent data, mounted at `/opt/data` |
| `/home/aiagent/.config/opencode` | OpenCode configuration |
| `/home/aiagent/.local/share/opencode` | OpenCode data |
| `/home/aiagent/.cache/opencode` | OpenCode cache |
| `/home/aiagent/.kimi-code` | Kimi Code state |
| `/home/aiagent/.claude` and `.claude.json` | Claude Code state |
| `/home/aiagent/.config/git/config` | Shared container Git settings |
| `/home/aiagent/.local/share/ai-workbench/tools` | Custom tool Containerfiles |
| `/home/aiagent/.local/share/ai-workbench/gcp/contexts/<hash>` | GCP identity, token, and lifetime metadata |
| `/home/aiagent/.local/share/ai-workbench/cloudflare/contexts/<hash>` | Cloudflare token environment file |

`<hash>` is the SHA-256 of the resolved workspace path. Moving or cloning a repository requires configuring its cloud authorization again. Non-Git directories use their current directory path as the workspace.

GCP and Cloudflare authorization is loaded automatically into **all** agent and shell containers started for that configured workspace. `ai login` uses a separate workspace-free Codex login container.

Do not commit runtime state, tokens, service account keys, or copied agent authentication directories to Git. Only the setup script and this README are needed to distribute the workbench.

## Security model and limits

- Rootless Podman runs under the separate `aiagent` host account. Containers mount only the selected workspace, selected agent state, and configured cloud authorization.
- On the host, `aiagent` has ACL access to the entire `~/projects` tree. The one-project restriction is enforced by the launcher and its mounts, not by separate host accounts per project.
- Codex-based containers drop Linux capabilities and enable `no-new-privileges`. Hermes starts as namespace-local root for its official entrypoint and maps its service user to host `aiagent`; its launch settings differ from the Codex branch.
- Agent authentication directories are persistently mounted. Executed code can read the mounted agent credentials and cloud tokens. This setup does not isolate secrets from subprocesses or broker individual API requests.
- Containers share the host kernel. Network access is enabled; the launcher does not provide an egress allowlist.
- Default per-container limits are 8 GiB memory, four CPUs, and 1,024 processes. No host ports are published by the launcher. Change the launcher template in the setup script if you need different limits or networking.
- Images and packages are not pinned to immutable versions. Review upstream changes when updating.

Use these boundaries when deciding which repositories and cloud projects to authorize.

## Updates and troubleshooting

```bash
ai help
ai status
ai pull                  # Update base images and rebuild installed layers/agents
```

After downloading a newer setup script, run `bash setup-ai-workbench.sh --finish` to refresh the launcher. Use `ai pull` when you also want image updates. Rebuild custom layers after changing their Containerfiles.

| Problem | Action |
| --- | --- |
| Missing `/run/user/<aiagent UID>` | Reboot, then rerun setup. |
| Project ACL validation fails | Check the displayed ACL masks and directory traversal permissions. Home traversal is sufficient; the project directory needs read/write/traverse access. Rerun setup after moving new projects into the tree if their ACLs do not permit access. |
| Tool unavailable in a container | Add it to the relevant tool Containerfile, run `ai tools build`, and restart the container. |
| Optional agent not installed | Run `ai install opencode`, `ai install kimi`, or `ai install claude`. |
| GCP token expired | Run `ai gcp refresh` from the host in the same repository. |
| GCP impersonation still denied after retries | Inspect the service account's effective IAM policy, the host's selected gcloud account, and any deny policies. A successful policy write does not guarantee immediate propagation. |
| Twelve-hour GCP token unavailable | One-hour fallback is expected without the lifetime exception. An Organization Policy Administrator can configure it. |
| GCP context exists but gcloud images are missing | Run `ai gcp install`. |
| Cloudflare request denied | Check the token's status, expiration, and resource/product permissions in Cloudflare; reimport and restart containers after rotation. |
| Repository outside `~/projects` or external Git worktree | Use a supported repository layout or adapt the launcher before using it. |

The project has no automated uninstaller. Removing the launcher alone does not remove the host account, ACLs, sudoers rule, container images, persistent credentials, or cloud IAM changes.

## References

- [Podman documentation](https://docs.podman.io/)
- [Google service account impersonation](https://docs.cloud.google.com/docs/authentication/use-service-account-impersonation)
- [Google access-token lifetimes](https://docs.cloud.google.com/sdk/gcloud/reference/auth/print-access-token)
- [Google IAM propagation](https://docs.cloud.google.com/iam/docs/access-change-propagation)
- [Cloudflare API token creation](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)
- [Cloudflare Workers authorization](https://developers.cloudflare.com/workers/authorization/)

## Validation

The setup script and embedded launcher have been checked with Bash syntax validation. GCP fallback and retry behavior has been exercised with mocked commands. This is not a substitute for validating installation, container images, and cloud permissions in your own environment.
