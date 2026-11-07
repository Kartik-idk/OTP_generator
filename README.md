# Secure OTP Generator & Verification System

[![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Tests-29%20Passing-brightgreen.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External-success.svg)]()
[![Code Style](https://img.shields.io/badge/Code%20Style-PEP%208-informational.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight, cryptographically secure Command-Line One-Time Password (OTP) generation and verification system written in pure Python.

Originally designed as an academic mini-project and optimized into a robust, secure-by-design reference implementation using Python's standard library `secrets` module and constant-time string comparisons.

---

## 📌 Problem Statement

Simple OTP generators often suffer from serious security flaws:
1. **Insecure Pseudo-Random Number Generators (PRNGs):** Relying on standard `random` (Mersenne Twister `MT19937`) exposes state, allowing attackers to predict subsequent OTP sequences after observing earlier values.
2. **Timing Side-Channel Vulnerabilities:** Standard string equality (`==`) terminates character comparison at the first mismatched byte, leaking OTP character matches through response-time analysis.
3. **Leading-Zero Loss:** Formatting numerical random values directly as integers drops leading zeros (e.g., generating `42` instead of `000042`), corrupting fixed-length tokens and shrinking the effective keyspace.
4. **Fragile Input Handling:** Applications crash with unhandled tracebacks when users enter non-numeric characters, submit empty input, or press interrupt keys (`Ctrl+C`, `Ctrl+D`).

**Secure OTP Generator** resolves these issues by pairing cryptographically secure pseudo-random number generation (CSPRNG) with constant-time verification (`secrets.compare_digest`), zero-padding preservation, and resilient terminal input validation.

---

## ✨ Key Features

- **🔐 Cryptographically Secure Randomness:** Powered by Python's `secrets` module (utilizing OS-level CSPRNG entropy sources: `/dev/urandom` on Unix-like systems and `BCryptGenRandom` on Windows).
- **⏱️ Constant-Time Verification:** Uses `secrets.compare_digest()` to mitigate timing side-channel attacks during authentication.
- **0️⃣ Preserved Leading Zeros:** Zero-padded fixed-width string formatting ensures all values spanning the full keyspace ($000000$ to $999999$) maintain uniform token length.
- **🛡️ Strict Input Sanitization:**
  - Rejects empty, whitespace-only, and non-ASCII characters.
  - Enforces exact token length and ASCII digit restrictions (`0-9`).
  - Safely trims leading and trailing whitespace from submitted inputs.
- **⚡ Clean CLI Signal Handling:** Traps `KeyboardInterrupt` (`Ctrl+C`) and `EOFError` (`Ctrl+D`) to exit cleanly without dumping stack traces.
- **📦 Zero External Dependencies:** 100% Python standard library for instant zero-setup portability.
- **🧪 Comprehensive Test Coverage:** 29 automated unit tests covering generation, validation, verification, boundary conditions, and CLI integration.

---

## 🔒 Security Architecture & Threat Model

| Security Concern | Implementation Approach | Status / Protection |
| :--- | :--- | :--- |
| **Randomness Predictability** | `secrets.randbelow(1_000_000)` | **Protected**: Non-deterministic OS entropy |
| **Leading Zero Truncation** | Format specifier `f"{token:06d}"` | **Protected**: Full 6-digit keyspace ($10^6$ combinations) |
| **Timing Attacks** | `secrets.compare_digest()` | **Protected**: Constant-time comparison |
| **Unicode Digits Injection** | `str.isascii() and str.isdigit()` | **Protected**: Strict ASCII `[0-9]` boundary |
| **Unexpected Types** | Defensive `isinstance()` checks | **Protected**: No unexpected type crashes |
| **Process Interruption** | Signal trapping (`SIGINT` / `EOF`) | **Protected**: Clean user-facing exit message |

---

## ⚠️ Security Limitations & Project Scope

> [!IMPORTANT]
> **Scope Disclaimer**: This project is designed as a secure local reference and educational CLI utility, **not** a complete multi-factor authentication (MFA) cloud service.

Please note the following boundaries:
1. **Local Terminal Display:** In this demonstration CLI, the generated OTP is displayed on standard output to enable manual verification. In an enterprise authentication architecture, OTPs must be transmitted out-of-band (e.g., via SMS, email, or TOTP authenticator apps) and never displayed on the verifier terminal.
2. **Single-Use State & Expiration:** This local tool demonstrates one-shot generation and immediate verification. It does not include an in-memory TTL cache (e.g., Redis) or time-window expiration (RFC 6238 TOTP).
3. **Rate Limiting:** As a local CLI script, brute-force attempts are bound by process execution. In network-facing environments, rate limiting (e.g., maximum 3 attempts before token invalidation) should be enforced.

---

## 🛠️ Technologies Used

* **Language:** Python 3.9+ (tested up to 3.14)
* **Standard Library Modules:**
  * `secrets`: Cryptographically strong random number generation and constant-time string comparison.
  * `sys`: System exit codes and runtime IO.
  * `unittest`: Built-in automated test framework.
  * `unittest.mock`: Deterministic boundary testing and CLI signal mocking.

---

## 📋 Requirements

* Python 3.9 or higher.
* Operating System: Linux, macOS, or Windows.
* No pip packages or third-party dependencies required.

---

## 🚀 Installation & Execution

### 1. Clone or Open the Repository
```bash
git clone https://github.com/Kartik-idk/OTP_generator.git
cd OTP_generator
```

### 2. Run the Application
Execute the script using Python:
```bash
python3 OTP_Generator.py
```
Or run using `make`:
```bash
make run
```

---

## 🖥️ Example Terminal Output

### Scenario 1: Successful Verification
```text
==================================================
      Secure OTP Generator & Verification CLI
==================================================
[+] Your generated OTP is: 844830
[!] Note: Displayed for local demonstration/testing.
--------------------------------------------------
Enter the 6-digit OTP: 844830
[+] Authentication successful: OTP verified.
```

### Scenario 2: Incorrect OTP Submitted
```text
==================================================
      Secure OTP Generator & Verification CLI
==================================================
[+] Your generated OTP is: 891942
[!] Note: Displayed for local demonstration/testing.
--------------------------------------------------
Enter the 6-digit OTP: 000000
[-] Authentication failed: Incorrect OTP.
```

### Scenario 3: Non-Numeric Characters
```text
==================================================
      Secure OTP Generator & Verification CLI
==================================================
[+] Your generated OTP is: 456265
[!] Note: Displayed for local demonstration/testing.
--------------------------------------------------
Enter the 6-digit OTP: abc123
[-] Authentication failed: OTP must contain numeric digits (0-9) only.
```

### Scenario 4: Incorrect Digit Length
```text
==================================================
      Secure OTP Generator & Verification CLI
==================================================
[+] Your generated OTP is: 312094
[!] Note: Displayed for local demonstration/testing.
--------------------------------------------------
Enter the 6-digit OTP: 3120
[-] Authentication failed: Expected 6 digits, but received 4.
```

---

## 🧪 Testing Instructions

The project includes a comprehensive unit test suite in `tests/test_otp_generator.py` testing generation, validation, constant-time verification, leading zeros, and CLI signal handling.

Run tests using the built-in test runner:
```bash
python3 -m unittest discover tests -v
```

Or run via `make`:
```bash
make test
```

### Test Suite Summary
```text
Ran 29 tests in 0.002s

OK
```

---

## 💡 Future Improvements

- [ ] **RFC 6238 TOTP Support:** Add Time-based One-Time Password support with shared secret HMAC generation.
- [ ] **Configurable Expiry Window:** Add time-to-live (TTL) validation tracking generation timestamps.
- [ ] **Attempt Throttling:** Introduce maximum retry counters to lock out verification after 3 failed attempts.
- [ ] **Out-of-Band Delivery Mock:** Add mock delivery plugins (SMTP/email or SMS gateway integration).

---

## 📄 License

This project is open-source and distributed under the [MIT License](LICENSE).

