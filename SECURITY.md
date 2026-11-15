# Security Policy

BlindBean is a cryptography library, so a vulnerability in it can expose the data it exists to
protect. Reports are welcome and are handled privately until a fix is available.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub's vulnerability reporting:

1. Open <https://github.com/PIsberg/blindbean/security/advisories/new>
   (or the repository's **Security** tab, then **Report a vulnerability**).
2. Describe the issue, the affected module and version (or commit), and how to reproduce it.
   A failing test or a minimal program is the most useful form.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement of the report | within 7 days |
| First assessment (confirmed, needs info, or not a vulnerability) | within 14 days |
| Fix or mitigation for a confirmed issue | depends on severity; you are kept informed |

Once a fix is released, the advisory is published with credit to the reporter unless you ask
to stay anonymous.

## Supported versions

BlindBean has not yet made a stable release. Fixes land on `main` and ship in the next release;
older pre-release versions are not patched.

| Version | Supported |
|---|---|
| `main` / latest release | yes |
| anything older | no |

## Scope

In scope: the library modules in this repository (annotations, processor, core, runtime, fhe,
junit), the native SEAL bridge under `blindbean-fhe/native`, and the release and CI workflows.

Out of scope, because they are documented limits of the design rather than defects:

- the absence of integrity or authenticity on ciphertexts (the schemes are malleable by design),
- timing side channels in `BigInteger.modPow` on the pure-Java Paillier path,
- the CKKS approximation error,
- vulnerabilities in Microsoft SEAL itself (report those upstream; tell us too if BlindBean's use
  of SEAL makes them reachable).

[docs/SECURITY-AND-LIMITATIONS.md](docs/SECURITY-AND-LIMITATIONS.md) describes each of these
and the operational rules (key handling, noise budget, parameter floors) that keep BlindBean safe
to use.
