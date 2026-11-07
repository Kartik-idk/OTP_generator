"""Generate and verify a six-digit one-time password (OTP)."""

import secrets


def generate_otp():
    """Return a securely generated six-digit OTP as a string."""
    return f"{secrets.randbelow(1_000_000):06d}"


def verify_otp(generated_otp, entered_otp):
    """Return True when the entered OTP matches the generated OTP."""
    return generated_otp == entered_otp


def main():
    otp = generate_otp()
    print(f"Your generated OTP is: {otp}")

    entered_otp = input("Enter the 6-digit OTP: ").strip()

    if not entered_otp.isdigit() or len(entered_otp) != 6:
        print("Authentication failed: please enter exactly six digits.")
    elif verify_otp(otp, entered_otp):
        print("Authentication successful.")
    else:
        print("Authentication failed: incorrect OTP.")


if __name__ == "__main__":
    main()
