# Security policy

## Reporting scanner vulnerabilities

Do not file a public issue containing live credentials, malware samples, private paths, or incident evidence. Report parser bypasses, unsafe file handling, command injection, IOC validation failures, or false-clean conditions privately to the repository maintainer.

Include the scanner version, operating system, command line with secrets removed, report coverage section, and a minimal safe reproducer. Never attach a real credential or execute a suspected payload to create a reproducer.

## Safe-development rules

- Tests must use synthetic inert fixtures only.
- Do not add install-time scripts or third-party runtime dependencies without explicit security review.
- Archive parsers must remain bounded and non-extracting.
- New external IOC sources require HTTPS, host pinning/allowlisting, provenance, validation, and regression checks.
- Any change that can turn an incomplete check into a clean exit requires dedicated regression tests.
