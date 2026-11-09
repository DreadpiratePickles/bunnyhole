# Security Policy

## Supported versions

Bunnyhole is pre-1.0. Only the latest release on `main` gets security fixes. There are no backports.

| Version | Supported |
|---|---|
| latest `main` (0.2.x) | yes |
| anything older | no |

## Reporting a vulnerability

Please report privately. Do not open a public issue, pull request or discussion for a suspected vulnerability.

1. Open the repository's **Security** tab and choose **Report a vulnerability**. This is a private
   [GitHub security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).
2. Include the affected version or commit, the surface (CLI, TUI, War-Room API/UI, MCP server), steps to
   reproduce, and the impact you observed. A minimal proof of concept helps.
3. Leave out any real person's data. Use fictional selectors such as `example.com` or `203.0.113.0/24`.

We aim to acknowledge a report within 7 days and to agree a disclosure date with you. We will credit you in
the advisory unless you ask us not to. This is a volunteer project with no bug bounty.

## Scope

Bunnyhole is a **passive OSINT tool**. It queries public sources and records what they return, and it runs
locally for one analyst. Read [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) for what it is for.

**In scope** (examples of what we treat as a vulnerability):

- **Credential or secret leaks**: an API key from the vault (`~/.bunnyhole/api_keys.env`), the
  `BUNNYHOLE_API_TOKEN`, or a credential entered as a selector ends up in logs, reports, case files, the UI,
  an outbound request or an error message.
- **SSRF**: a crafted selector, redirect or DNS answer makes Bunnyhole reach a loopback, private, link-local
  or cloud-metadata address, or makes it bypass the configured `--proxy` / `--tor` route.
- **Auth bypass in the War-Room**: reaching a mutating API route without the token when one is configured,
  defeating the loopback-only / Host-header protection, DNS rebinding, CSRF, or cross-origin reads.
- **Injection**: XSS in the War-Room or TUI from untrusted OSINT data, shell or argument injection through a
  selector passed to an arsenal tool, path traversal in case or file handling.
- **Unsafe persistence**: vault or case files written with permissions other users can read.
- **Safety gate bypass in the PI stream**: getting `--pi` to run breach/credential sources, skip its purpose
  gate, or leave a redacted value in a report, where the documentation says that cannot happen.
- **Denial of service** from a single crafted input (unbounded memory, a hang with no timeout).

**Out of scope:**

- What third-party sources return (wrong, stale or offensive data) and their rate limits or terms.
- Findings that need an already compromised machine or account, or a malicious local user with your privileges.
- The optional external tools that `bunnyhole arsenal` can install (sherlock, holehe and the rest). Report
  those to their own projects.
- Exposing the War-Room beyond loopback by your own means (a reverse proxy, port forward or tunnel) without
  `BUNNYHOLE_API_TOKEN`. `bunnyhole serve` itself refuses a non-loopback `--host` without the token.
- The phrase screens in the PI stream not catching every wording. Their limits are documented, and they are
  a safety net, not a guarantee. A bypass of a documented guarantee is in scope, as listed above.
- Misuse of the tool itself. That is an acceptable-use matter, not a vulnerability.

## Handling secrets as a contributor

Never commit a real key, token or personal data, including in tests. Tests use fake sentinel values only, and
CI runs a gitleaks secret scan on every push and pull request. See [`CONTRIBUTING.md`](CONTRIBUTING.md).
