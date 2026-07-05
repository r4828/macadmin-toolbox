# macadmin-toolbox

Scripts, configuration profiles, and other odds and ends I've built for managing Macs with Jamf Pro and other MDMs. They're here so other Mac admins can use them, break them, fix them, and send the fixes back.

Everything is MIT licensed. Use it in your own environment, fold it into your own repo, build a product on top of it. The one thing I ask is that you keep the copyright and license notice, which is all the MIT license requires anyway.

## What's in here

`jamf/` holds Jamf Pro specific work: extension attributes, policy scripts, API tooling, Smart Group helpers.

`mdm/` holds vendor-neutral scripts that run the same no matter which MDM pushed them, whether that's Jamf, Intune, Mosyle, Kandji, or you running it by hand in Terminal.

`configs/` holds configuration profiles (`.mobileconfig`), plist snippets, and managed-preference examples.

`docs/` holds standards and notes for people contributing.

Each folder has its own README explaining what belongs there.

## Before you run anything

Read the script first. That goes double for code off the internet that runs as root across a fleet of Macs. Everything here is provided as-is with no warranty (see [LICENSE](LICENSE)). Test on a spare machine or a pilot Smart Group before it gets anywhere near production.

Most scripts carry a header comment covering what they do, where they're meant to run (a Jamf policy, a login script, standalone Terminal, a LaunchDaemon), the parameters they expect, and the macOS versions they've been tested on.

## Contributing

Pull requests are the whole point. Fixed a bug, wrote a script, sharpened the docs? Open a PR. A typo fix is as welcome as a new tool.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules on script headers, secrets, and testing. First-timers welcome.

## A word on secrets

Nothing here should contain a real API secret, token, password, or live server URL. If you spot one, report it privately (see [SECURITY.md](SECURITY.md)) instead of opening a public issue that points everyone at it.

## License

MIT. Full text in [LICENSE](LICENSE).
