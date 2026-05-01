# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security reports.**

Report vulnerabilities privately via the repository's **Security** tab → **Report a vulnerability** (GitHub Private Vulnerability Reporting). This keeps the report private to the maintainers until a fix ships.

Include:

- A description of the vulnerability.
- Steps to reproduce, with a minimal test case if possible.
- The potential impact (confidentiality, integrity, availability).
- A suggested fix if you have one.
- Whether you would like credit in the disclosure.

We aim to acknowledge new reports within **72 hours** and provide a remediation timeline shortly after. Coordinated disclosure is expected — please do not publicly share the vulnerability until a patch has been released.

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x (current) | Security fixes for the active patch series |
| Pre-0.1.0 | Not supported |

Once 0.2 ships, 0.1.x will continue to receive critical security fixes for at least six months.

## Scope

In scope: vulnerabilities in Hokora's own code (this repository).

Out of scope (please report upstream):

- [Reticulum (RNS)](https://github.com/markqvist/Reticulum)
- [LXMF](https://github.com/markqvist/lxmf)
- [SQLCipher](https://www.zetetic.net/sqlcipher/)
- [PyNaCl](https://github.com/pyca/pynacl) / [libsodium](https://doc.libsodium.org/)

## Security overview

Hokora's security model — sealed-channel invariant, federation handshake, forward-secret epochs, file-mode discipline, observability auth — is documented in the operator runbooks under `docs/runbooks/`. Start with [00-overview.md](docs/runbooks/00-overview.md) and follow links from there.
