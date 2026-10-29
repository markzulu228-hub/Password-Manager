# Security

## How your data is protected
* The vault file is encrypted with AES-256-GCM. The key is derived from your master
  password with PBKDF2-HMAC-SHA256 (210,000 iterations, random 16-byte salt).
* Tampering with the file is detected (GCM authentication); a wrong master password
  cannot decrypt anything.
* There is no master-password recovery. If you forget it, the data is gone.
* The breach check sends only the first 5 characters of a SHA-1 hash to
  haveibeenpwned.com (k-anonymity). Passwords never leave your computer.

## Limits you should know about
* This project has **not** had an independent security audit. For high-value secrets,
  prefer a mature, audited password manager.
* Anything with access to your computer while the vault is unlocked (malware, a
  screen-capture tool) can see what you can see.
* Auto-type briefly places text on the clipboard.
* The unlock delay after wrong guesses is in memory only. It slows casual guessing at
  the prompt, but it does not protect a copy of the vault file; the master password
  strength does.
* CSV exports are plain text. Delete them after use.

## Reporting a problem
Open a GitHub issue for ordinary bugs. For a vulnerability, use the repository's
**Security > Report a vulnerability** option (enable "Private vulnerability reporting"
in Settings > Code security) rather than posting details publicly.
