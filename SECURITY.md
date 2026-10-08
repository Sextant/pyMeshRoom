# Security policy

## Supported code

Security fixes are made on the current `main` branch of pyMeshRoom.

## Reporting a vulnerability

Please do not publish a proof of concept, private configuration, credentials,
or a virtual-repeater private key in a public issue. Use GitHub's private
security-advisory reporting flow for this repository when it is available, and
include the affected pyMeshRoom commit, deployment details needed to reproduce
the issue, and the potential impact.

## Deployment safety

pyMeshRoom installations keep credentials, member data, shared secrets, and
optional Virtual Repeater private keys in local runtime files. Keep those files
out of Git, restrict the configuration to its owner (`chmod 600`), and place
any Internet-facing dashboard behind HTTPS and appropriate access controls.

## Maintainer checklist

For the public GitHub repository, enable secret scanning with push protection,
Dependabot alerts, and branch protection for `main`. Review bundled dependency
updates, including the Paho MQTT source and checksum recorded in
`meshroom/vendor/README.md`, before publishing a release.
