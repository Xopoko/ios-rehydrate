# Security policy

## Reporting

Report vulnerabilities privately with GitHub's **Report a vulnerability** button on the
repository's Security tab, not in a public issue.

Don't attach real IPAs, backups, receipts, pairing records, logs, or device/account identifiers.
A synthetic reproducer is best.

Only the latest release gets fixes.

## Scope

In scope:

- parsing untrusted IPAs and backups;
- confining device-requested filesystem access during backup;
- receipt and eligibility checks before `Upgrade`;
- leaking identifiers or secrets into output, receipts, or errors.

Out of scope:

- a compromised host, USB stack, or dependency;
- Apple's own authorization decisions;
- the residual risks listed in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#untrusted-inputs-and-how-they-are-handled).
