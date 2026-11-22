# Installation and release gate

This is experimental source code only. The Dockerfile starts a non-root HTTP UI but DOES NOT install or provide the host Unix-socket agent. The interface cannot manage a fresh HOUZZkit F1 until the system components have been separately provisioned by an administrator. It is not a standalone proxy.

Privileged agent: root:f1console is an example socket-group security boundary from one development prototype, not an installation recipe. It requires an existing Mihomo service, valid proxy groups and a known recoverable gateway setup.

The demonstration routing groups AI_FIXED_US, NON_HK_REGION, AIRPORT_GENERAL, AI-US-DEDICATED are placeholders and must not be installed into another user's live system without a safe migration. No router DHCP change, host-wide transparent traffic interception or root Docker socket is authorized by this source package.

The LAN UI uses plain HTTP. Implement trusted HTTPS, first-pairing, auth rekeying, session invalidation and network isolation before real production or shared-network use. Preserve private user volumes and never publish a production configuration or subscription URL.

Public release checklist:
1. Pass all offline Python and JS tests.
2. Build a reproducible ARM64 artifact with a reviewed base image and immutable digest; prove process user and network isolation.
3. Perform recoverable ARM64/Mihomo/systemd tests on a disposable Linux VM or spare F1 and verify state on SIGKILL, ENOSPC and hard reset.
4. Build a complete HOS app definition using config.yml and flow_config.yml plus all resource files, without placeholders or root Docker API.
5. Verify a true fresh HOS installation, upgrade, clean export/import onto another device and uninstall preserving user data.
6. Submit an upstream pull request for maintainer review. Store inclusion requires upstream approval. Do not claim release merely because the GitHub repo is public.

Upstream HOS app development docs: https://yinbaiyuan.github.io/developers/houzzkit_docker_package_make_advance.html
