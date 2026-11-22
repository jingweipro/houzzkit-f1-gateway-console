# HOUZZkit F1 Gateway Console

Independent, community-developed Chinese management dashboard and experimental Mihomo gateway control agent for HOUZZkit F1.

**Development preview — NOT an installable HOS application, not a published HDP, and not recommended on a production router.** The sample Dockerfile contains the unprivileged web UI only; its privileged Unix-socket agent still requires a site-specific, reviewed install and compatible existing Mihomo configuration. The public source is sanitized and differs from the currently running private configuration.

## Implemented and tested in isolated environments
- Browser dashboard, authenticated sessions, CSRF protection, operation throttling
- Provider validation through HTTPS with pinned public DNS answers and certificate verification; new subscriptions are saved but **not activated**
- Read-only node inventory, optional live testing when the local agent is configured
- Guarded regional priority changes, persistent transaction receipt and rollback handling
- Offline failure injection, process crash scenarios and ARM64 read-only preflight
- 62 offline tests in the original development branch, plus public fixture tests (check CI)

## Not implemented / not verified
- Clean-device self-installer or safe automatically installed host agent
- General subscription activation and routing strategy
- Trusted HTTPS for shared LAN environments or secure first-time pairing
- Published reproducible ARM64 image
- Verified HOS native HDP containing all resource files and clean-device import
- Acceptance by HOUZZkit OS application store maintainers

The included HOS manifest is deliberately a **source template with invalid placeholder image fields**, and is not a released installer. Do not rename an archive to .hdp or assume the upstream project accepted this program.

## Development and tests

Requires Python 3.13 with PyYAML, and Node.js.

Run Python unit tests with: python3 -m unittest discover -s tests -v

Run the source checker with: python3 tools/check_release.py

Check frontend JS with: node --check app/app.js

Check ARM64 lab script syntax with: bash -n tools/arm64_lab.sh

See ARM64-LAB.md and INSTALL-AND-RELEASE.md for test-only safety requirements.

## Collaboration, upstream and updates
Source and independent version history: https://github.com/jingweipro/houzzkit-f1-gateway-console

Upstream HOS community app definitions: https://github.com/yinbaiyuan/houzzkit-application-store

We intend to submit a tested app definition after the ARM64 image, HOS native resource packaging and real clean-device installation work. Upstream acceptance and future HOS OS integration are not guaranteed; new source commits are **not** automatic installed app updates.

Security: do not expose the HTTP administration interface to the internet, use it on shared Wi-Fi or report live subscription tokens in public issues. No personal credentials or production data are included.

License: MIT. Not affiliated with or endorsed by HOUZZkit.
