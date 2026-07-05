# jamf/

Scripts and tooling specific to Jamf Pro.

This is the place for anything that assumes Jamf: policy scripts that read parameters from `$4` onward, extension attributes, Jamf Pro API scripts, Smart Group and Advanced Search helpers, and package postinstall scripts run from a policy.

## Conventions

Extension attributes print a single `<result>...</result>` block to stdout. Once there are a few, move them into an `extension-attributes/` subfolder.

Policy scripts get their first custom parameter as `$4`; Jamf reserves `$1`, `$2`, `$3` for mount point, computer name, and username. Document which parameter is which in the header.

API scripts should use the API client credentials flow (a client ID and secret), not a username and password. Never hard-code credentials. Read them from a parameter or a profile.

## If it isn't Jamf-specific

If a script would run the same way under Intune, Mosyle, Kandji, or by hand, it belongs in `mdm/` instead, where admins on other platforms will find it.
