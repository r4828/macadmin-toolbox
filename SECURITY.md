<!-- SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors -->
<!-- SPDX-License-Identifier: MIT -->

# Security policy

## Reporting a vulnerability or a leaked secret

Please report any of these privately:

- An API key, client secret, token, or password committed to the repo, in current files or anywhere in git history.
- A script that does something destructive without warning.
- A URL or credential that points at a real, live environment.

Do not open a public issue for these. A public issue tells everyone where the secret is before it can be pulled.

Use GitHub's private reporting instead: open the **Security** tab and click **Report a vulnerability**, or reach the maintainer through their GitHub profile ([@r4828](https://github.com/r4828)).

## What happens next

I'll confirm the report, then remove or rotate whatever leaked. If a secret made it into a commit, I'll rewrite the git history, because deleting it from the latest commit isn't enough. It stays in history until the history is rewritten.

Reporters who want credit get it.

## Scope

The scripts and profiles here run on managed Macs, often as root. Read and test every one before running it. The [LICENSE](LICENSE) says it plainly: no warranty. A script that works in my environment can still break yours.

Reporting that a script *could* be dangerous in a way its header doesn't mention counts as a valid report too. Clearer docs make the whole repo safer.
