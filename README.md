# @sendshieldfiles/crypto

Public source for the client-side encryption used by [SendShield Files](https://sendshieldfiles.com).

Files are encrypted in the browser before upload. This package is the implementation described in the [cryptographic architecture](https://sendshieldfiles.com/security): AES-256-GCM in 16 MiB chunks, Argon2id passphrase wrapping, and X25519 sealing for file requests. Decryption keys stay in the URL fragment.

This repository is updated when that crypto package changes. It is published here so the encryption code can be read. It is not published to npm.

## Layout

- `src/aes.ts` — file keys and AES-256-GCM chunk encryption
- `src/header.ts` — encrypted file header
- `src/kdf.ts` — Argon2id wrapping and the vault canary
- `src/seal.ts` — X25519 seal for file-request keys
- `src/pow.ts` — memory-hard proof of work for abuse prevention
- `src/*.test.ts` — checks you can run locally

## Tests

```bash
npm install
npm test
```

## License

MIT. Copyright 2026 SendShield Files.
