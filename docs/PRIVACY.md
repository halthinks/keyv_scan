# Privacy and evidence handling

The scanner can report local paths, usernames embedded in paths, package names/versions, matching process command lines, file sizes, permissions, and operational errors. Treat reports as incident evidence.

The scanner deliberately does not read the contents of:

- `~/.config/gh-token-monitor/token`
- `~/.config/gh-token-monitor/handler`

It reports only that those documented paths exist, plus non-content metadata. Other candidate scripts and service definitions may be read and hashed because their content is necessary for detection.

Store reports in an access-controlled incident location. Redact only copies intended for external sharing; preserve an original evidence copy and its hash.
