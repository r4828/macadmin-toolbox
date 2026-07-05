<!-- SPDX-FileCopyrightText: 2026 Robert Flanagan and macadmin-toolbox contributors -->
<!-- SPDX-License-Identifier: MIT -->

# configs/

Configuration profiles and preference files.

## What fits here

- Configuration profiles (`.mobileconfig`), exported unsigned so they stay readable and editable.
- Plist and preference examples (`.plist`) that document a managed preference key.
- Notes on which payload keys do what, since Apple's own documentation is sometimes thin.

## Before you commit a profile

Strip anything that identifies your environment: organization name, server URLs, MDM UUIDs, certificate payloads. Swap in placeholders.

A `.mobileconfig` is XML. Open it in a text editor and read it before committing. A signed profile is opaque, so commit the unsigned source.

Say what the profile does and which macOS versions honor the keys. Payload behavior shifts between releases; a key that works on macOS 15 may be ignored on macOS 13.
