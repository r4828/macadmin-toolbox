# Contributing to macadmin-toolbox

Thanks for pitching in. This repo grows when people send their fixes and their own tools back to it. Here's how to do that cleanly.

## Opening a pull request

1. Fork the repo and branch off `main`.
2. Put your script in the folder that fits (`jamf/`, `mdm/`, or `configs/`). Not sure? Put it where it best fits and say so in the PR. We'll sort it out.
3. Give it a header comment (see below).
4. Run `shellcheck` on shell scripts. CI runs it too, so doing it locally saves a round trip.
5. Open the PR against `main` and fill out the template.

## Script header

Every script starts with a comment block that answers the questions the next admin will have:

```bash
#!/bin/bash
# Name:        reset-something.sh
# Purpose:     One or two sentences on what it does.
# Context:     Where it runs: Jamf policy, login/logout, standalone, LaunchDaemon.
# Parameters:  $4 = username, $5 = ... (Jamf passes custom params starting at $4)
# Tested on:   macOS 14 Sonoma, macOS 15 Sequoia
# Author:      Your Name (@yourhandle)
```

Adjust the comment style for the language. Python and zsh scripts want the same information.

## No secrets, ever

Do not commit any of these:

- API client IDs or client secrets
- Bearer tokens or API keys
- Passwords of any kind
- A real server URL for a live environment (`yourcompany.jamfcloud.com`)
- Serial numbers, asset tags, or anything that identifies real hardware or people

Use placeholders: `YOUR_JAMF_URL`, `CLIENT_ID`, `example.jamfcloud.com`. Read your diff before you push. Git keeps secrets even after you delete them in a later commit, so if one slips through, flag it in the PR and we'll scrub the history.

## Style

- Shell scripts should pass `shellcheck` with no warnings. If you have to ignore a check, ignore it inline with a comment explaining why.
- Quote your variables. `"$var"`, not `$var`.
- Use a full interpreter path (`#!/bin/bash` or `#!/bin/zsh`), not `#!/usr/bin/env` guesswork. Managed Macs run these as root in a known environment.
- Keep it readable. The next person to touch your script is a tired admin at 2pm during an incident.

## What gets merged

- The script does what its header says.
- It has no secrets.
- Shell scripts pass `shellcheck`.
- It won't quietly nuke a machine. Anything destructive (deletes data, wipes, resets) needs a clear header warning and either a confirmation step or a documented reason there isn't one.

Maintainers review on their own time, so a little patience helps. If a PR sits a while, a polite nudge is fine.

## Found a security problem?

If you spot a committed secret or a script that does something dangerous without warning, see [SECURITY.md](SECURITY.md) and report it privately rather than in a public issue.
