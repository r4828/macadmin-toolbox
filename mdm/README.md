# mdm/

Vendor-neutral scripts. If it runs on macOS regardless of which MDM pushed it, it goes here.

Jamf, Intune, Mosyle, Kandji, Addigy, or a script you run by hand in Terminal: the code in this folder shouldn't care. No `$4` Jamf parameter assumptions, no vendor-specific API calls. Read configuration from arguments, environment, or a managed profile.

## What fits here

- macOS shell and zsh scripts for everyday admin work: cleanup, reporting, remediation.
- Python helpers that don't lean on a specific MDM's SDK.
- LaunchDaemons and LaunchAgents, with the `.plist` and its companion script kept together.
- `mdmclient` and profile inspection helpers.

## What doesn't

Anything that reads Jamf policy parameters or calls a vendor's API belongs next to that vendor. Today that means `jamf/`. If this repo picks up tooling for another platform, that platform gets its own folder.
