"""Generate and verify cryptographically secure one-time passwords (OTP).

This module provides CSPRNG-based OTP generation using Python's `secrets` module
and constant-time verification using `secrets.compare_digest` to prevent timing
side-channel attacks.
"""

import secrets
import sys

DEFAULT_OTP_LENGTH: int = 6


def generate_otp(length: int = DEFAULT_OTP_LENGTH) -> str:
    """Return a cryptographically secure numeric OTP with leading zeros preserved.

    Parameters:
        length (int): The number of digits in the OTP (default is 6).

    Returns:
        str: A zero-padded numeric string of the specified length.

    Raises:
        ValueError: If length is not a positive integer between 4 and 10.
    """
    if not isinstance(length, int) or length < 4 or length > 10:
        raise ValueError("OTP length must be an integer between 4 and 10 digits.")

    upper_bound = 10**length
    token_value = secrets.randbelow(upper_bound)
    return f"{token_value:0{length}d}"


def is_valid_otp(otp: str, expected_length: int = DEFAULT_OTP_LENGTH) -> bool:
    """Validate that an OTP candidate is a string of exact length with ASCII digits only.

    Parameters:
        otp (str): The candidate OTP string.
        expected_length (int): Expected digit count (default is 6).

    Returns:
        bool: True if otp meets length and digit criteria, False otherwise.
    """
    if not isinstance(otp, str):
        return False
    if len(otp) != expected_length:
        return False
    return otp.isascii() and otp.isdigit()


def verify_otp(generated_otp: str, entered_otp: str) -> bool:
    """Return True when the entered OTP matches the generated OTP in constant time.

    Uses secrets.compare_digest to defend against timing side-channel attacks.

    Parameters:
        generated_otp (str): The original generated OTP.
        entered_otp (str): The candidate OTP submitted for verification.

    Returns:
        bool: True if both OTPs match exactly and are valid, False otherwise.
    """
    if not isinstance(generated_otp, str) or not isinstance(entered_otp, str):
        return False

    if not is_valid_otp(generated_otp, expected_length=len(generated_otp)):
        return False

    if not is_valid_otp(entered_otp, expected_length=len(generated_otp)):
        return False

    return secrets.compare_digest(generated_otp, entered_otp)


def run_cli() -> int:
    """Execute the interactive command-line OTP generation and verification flow.

    Returns:
        int: Exit status code (0 for success or clean exit, 1 for auth failure).
    """
    print("=" * 50)
    print("      Secure OTP Generator & Verification CLI")
    print("=" * 50)

    try:
        otp = generate_otp(DEFAULT_OTP_LENGTH)
        print(f"[+] Your generated OTP is: {otp}")
        print("[!] Note: Displayed for local demonstration/testing.")
        print("-" * 50)

        raw_input = input("Enter the 6-digit OTP: ")
        entered_otp = raw_input.strip()

        if not entered_otp:
            print("[-] Authentication failed: OTP cannot be empty.")
            return 1

        if not (entered_otp.isascii() and entered_otp.isdigit()):
            print("[-] Authentication failed: OTP must contain numeric digits (0-9) only.")
            return 1

        if len(entered_otp) != DEFAULT_OTP_LENGTH:
            print(
                f"[-] Authentication failed: Expected {DEFAULT_OTP_LENGTH} digits, "
                f"but received {len(entered_otp)}."
            )
            return 1

        if verify_otp(otp, entered_otp):
            print("[+] Authentication successful: OTP verified.")
            return 0

        print("[-] Authentication failed: Incorrect OTP.")
        return 1

    except (KeyboardInterrupt, EOFError):
        print("\n\n[-] Operation cancelled by user. Exiting cleanly.")
        return 0


def main() -> None:
    """Module entry point."""
    status_code = run_cli()
    sys.exit(status_code)


if __name__ == "__main__":
    main()
