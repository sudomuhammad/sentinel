# GitHub setup

Sentinel acts on GitHub through a GitHub App. Each run mints an installation token scoped to one repository that expires within the hour. The App's private key and the tokens stay on the host.

## Create the App

1. Go to Settings, Developer settings, GitHub Apps, New GitHub App.
2. Turn off webhooks.
3. Give it these repository permissions and nothing else:
   - Contents: read and write
   - Pull requests: read and write
   - Issues: read
   - Metadata: read (required)
4. Create the App, note its App ID, and generate a private key.
5. Install it on the repositories Sentinel should work on, and only those.

```sh
export SENTINEL_GITHUB_APP_ID=<app id>
export SENTINEL_GITHUB_APP_KEY_FILE=~/.config/sentinel/app.pem
chmod 600 ~/.config/sentinel/app.pem
```

## Protect the repository

The token can write contents, so the repository has to stop anything other than a reviewed pull request from reaching `main`. Sentinel only pushes `agent/*` branches, but these rules hold even if the harness has a bug.

- A ruleset on the default branch that requires a pull request with at least one approving review, blocks force pushes, and has no bypass for the App.
- A `CODEOWNERS` entry for `.github/` so workflow changes need an owner's review:

  ```
  /.github/ @your-handle
  ```

- Keep jobs that use secrets off agent branches. For `push` triggers:

  ```yaml
  on:
    push:
      branches-ignore: ["agent/**"]
  ```

  Or put those secrets in an environment with required reviewers.

## Try it

```sh
uv run sentinel run owner/repo --issue 1 --task "Fix the bug described in the issue"
```

The output ends with the pull request URL and the path to the run's audit log.
