# Simple Password Manager

A secure, local-first desktop password manager built with **Qt (C++)**, using modern, industry-standard cryptography provided by **libsodium** and **mbedTLS**.

This application is designed with a security-first approach: no cloud synchronization, no telemetry, and no external services. All data is encrypted locally using authenticated encryption and a memory-hard key derivation function.

---

## Overview

Simple Password Manager provides encrypted storage for credentials and sensitive information. The database is protected by a master password and encrypted using Argon2id-derived keys and ChaCha20-Poly1305 authenticated encryption.

The application focuses on correctness, cryptographic hygiene, and minimal attack surface.

---

## Security Architecture

### Key Derivation
- Algorithm: Argon2id
- Implementation: `crypto_pwhash` (libsodium)
- Salt: 32-byte cryptographically secure random value
- Limits: `OPSLIMIT_INTERACTIVE`, `MEMLIMIT_INTERACTIVE`

Argon2id is memory-hard, making GPU/ASIC brute-force attacks significantly more expensive.

### Encryption
- Algorithm: ChaCha20-Poly1305 (IETF variant)
- Mode: Authenticated Encryption with Associated Data (AEAD)
- Nonce: 12-byte cryptographically secure random value
- Integrity: Built-in authentication tag

This ensures both confidentiality and tamper detection.

### Randomness
- Secure RNG: mbedTLS CTR_DRBG
- Proper entropy seeding
- Rejection sampling for uniform integer generation
- No usage of insecure standard library RNGs

### Memory Hygiene
- Sensitive buffers cleared using `sodium_memzero`
- Master password wiped from memory upon lock
- Clipboard cleared automatically after 30 seconds
- Auto-lock after 5 minutes of inactivity

---

## Features

- Master password protected database
- Encrypted local storage (`~/.password_manager.dat`)
- Secure password generator
- Entry search functionality
- Add, edit, delete entries
- Change master password
- Automatic lock timeout
- Clipboard auto-clear

---

## Database Format

Encrypted file layout:

```
[32 bytes salt]
[12 bytes nonce]
[ciphertext + authentication tag]
```

All stored data is fully encrypted and authenticated.

---

## Dependencies

- Qt 6
- libsodium
- mbedTLS
- C++17 or newer

### Ubuntu / Debian

```bash
sudo apt install qt6-base-dev libsodium-dev libmbedtls-dev
```

---

## Build Instructions

### Using qmake

```bash
qmake
make
```

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

---

## Run

```bash
./password_manager
```

On first launch:
- Enter a master password.
- A new encrypted database will be created automatically.

---

## Threat Model

This application protects against:

- Offline file theft
- Brute-force attacks against encrypted database
- Ciphertext tampering
- Accidental clipboard exposure

This application does NOT protect against:

- Malware or keyloggers on the host system
- Compromised operating system
- Physical access while the database is unlocked
- Side-channel attacks

---

## Design Principles

- Local-first architecture
- Minimal external dependencies
- Strong cryptographic defaults
- Secure randomness only
- Memory hygiene awareness
- No cloud or remote attack surface

---

## Disclaimer

This is a personal project and has not undergone a formal security audit.  
Use at your own risk.

---

## License

Specify your preferred license here (e.g., MIT, Apache 2.0, GPLv3).
