"""Unit tests for the OTP Generator and Verification system."""

import io
import os
import sys
import unittest
from unittest.mock import patch

# Ensure the root directory containing OTP_Generator.py is on the import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import OTP_Generator


class TestOTPGeneration(unittest.TestCase):
    """Test suite covering cryptographically secure OTP generation."""

    def test_default_generation_length(self):
        """Default generated OTP must have exactly six characters."""
        otp = OTP_Generator.generate_otp()
        self.assertEqual(len(otp), 6)

    def test_numeric_characters_only(self):
        """Generated OTP must contain only ASCII decimal digits."""
        otp = OTP_Generator.generate_otp()
        self.assertTrue(otp.isascii() and otp.isdigit())

    def test_custom_valid_lengths(self):
        """OTP generation should support lengths between 4 and 10."""
        for length in (4, 5, 6, 7, 8, 9, 10):
            with self.subTest(length=length):
                otp = OTP_Generator.generate_otp(length)
                self.assertEqual(len(otp), length)
                self.assertTrue(otp.isascii() and otp.isdigit())

    def test_invalid_lengths_raise_value_error(self):
        """OTP generation should reject invalid lengths with ValueError."""
        invalid_lengths = [0, -1, 1, 2, 3, 11, 20, "6", 6.5, None]
        for invalid in invalid_lengths:
            with self.subTest(invalid_length=invalid):
                with self.assertRaises(ValueError):
                    OTP_Generator.generate_otp(invalid)  # type: ignore

    @patch("secrets.randbelow")
    def test_leading_zero_preservation(self, mock_randbelow):
        """Generated OTP must preserve leading zeros via zero-padding."""
        mock_randbelow.return_value = 42
        otp = OTP_Generator.generate_otp(6)
        self.assertEqual(otp, "000042")

        mock_randbelow.return_value = 0
        otp = OTP_Generator.generate_otp(6)
        self.assertEqual(otp, "000000")

        mock_randbelow.return_value = 7
        otp = OTP_Generator.generate_otp(6)
        self.assertEqual(otp, "000007")

    @patch("secrets.randbelow")
    def test_upper_boundary_generation(self, mock_randbelow):
        """Generated OTP must correctly format maximum values."""
        mock_randbelow.return_value = 999999
        otp = OTP_Generator.generate_otp(6)
        self.assertEqual(otp, "999999")

    def test_multiple_generations_entropy(self):
        """Generated OTPs should not produce constant duplicate values."""
        samples = [OTP_Generator.generate_otp() for _ in range(100)]
        self.assertTrue(all(len(s) == 6 and s.isdigit() for s in samples))
        # With 100 samples from 1,000,000 space, unique count should be very high
        unique_samples = set(samples)
        self.assertGreater(len(unique_samples), 85)


class TestOTPValidation(unittest.TestCase):
    """Test suite covering OTP format validation logic."""

    def test_valid_otp_strings(self):
        """Standard valid 6-digit numeric strings must validate."""
        valid_cases = ["000000", "123456", "999999", "045678"]
        for case in valid_cases:
            with self.subTest(case=case):
                self.assertTrue(OTP_Generator.is_valid_otp(case))

    def test_invalid_otp_non_string_types(self):
        """Non-string inputs must return False safely."""
        invalid_types = [None, 123456, 1234.56, ["1", "2", "3", "4", "5", "6"], {"otp": "123456"}]
        for case in invalid_types:
            with self.subTest(case=case):
                self.assertFalse(OTP_Generator.is_valid_otp(case))  # type: ignore

    def test_invalid_otp_lengths(self):
        """Strings of wrong length must return False."""
        invalid_lengths = ["", "1", "12", "123", "12345", "1234567", "12345678"]
        for case in invalid_lengths:
            with self.subTest(case=case):
                self.assertFalse(OTP_Generator.is_valid_otp(case))

    def test_invalid_otp_non_digit_characters(self):
        """Strings with letters, symbols, or whitespace must return False."""
        invalid_strings = ["abcdef", "12345a", "12 456", "12-456", "12.456", " 12345", "12345 "]
        for case in invalid_strings:
            with self.subTest(case=case):
                self.assertFalse(OTP_Generator.is_valid_otp(case))

    def test_reject_unicode_digits(self):
        """Non-ASCII unicode digits (e.g., Arabic-Indic) must return False."""
        arabic_indic_digits = "١٢٣٤٥٦"
        self.assertFalse(OTP_Generator.is_valid_otp(arabic_indic_digits))

    def test_custom_expected_length(self):
        """Validation helper should correctly handle custom expected lengths."""
        self.assertTrue(OTP_Generator.is_valid_otp("1234", expected_length=4))
        self.assertFalse(OTP_Generator.is_valid_otp("12345", expected_length=4))


class TestOTPVerification(unittest.TestCase):
    """Test suite covering constant-time OTP verification."""

    def test_correct_otp_match(self):
        """Identical valid OTPs must verify successfully."""
        self.assertTrue(OTP_Generator.verify_otp("123456", "123456"))

    def test_leading_zero_match(self):
        """OTPs with leading zeros must verify successfully."""
        self.assertTrue(OTP_Generator.verify_otp("000456", "000456"))

    def test_incorrect_otp_mismatch(self):
        """Differing OTPs must be rejected."""
        self.assertFalse(OTP_Generator.verify_otp("123456", "654321"))
        self.assertFalse(OTP_Generator.verify_otp("123456", "123457"))

    def test_empty_and_blank_rejection(self):
        """Empty or blank inputs must be rejected."""
        self.assertFalse(OTP_Generator.verify_otp("123456", ""))
        self.assertFalse(OTP_Generator.verify_otp("", "123456"))
        self.assertFalse(OTP_Generator.verify_otp("", ""))

    def test_non_digit_rejection(self):
        """Non-digit candidate inputs must be rejected."""
        self.assertFalse(OTP_Generator.verify_otp("123456", "abcdef"))
        self.assertFalse(OTP_Generator.verify_otp("123456", "12345!"))

    def test_differing_lengths_rejection(self):
        """Candidates with incorrect length must be rejected."""
        self.assertFalse(OTP_Generator.verify_otp("123456", "12345"))
        self.assertFalse(OTP_Generator.verify_otp("123456", "1234567"))

    def test_invalid_types_rejection(self):
        """Non-string arguments must return False without crashing."""
        self.assertFalse(OTP_Generator.verify_otp("123456", None))  # type: ignore
        self.assertFalse(OTP_Generator.verify_otp(None, "123456"))  # type: ignore
        self.assertFalse(OTP_Generator.verify_otp(123456, 123456))  # type: ignore

    @patch("secrets.compare_digest", wraps=OTP_Generator.secrets.compare_digest)
    def test_compare_digest_invoked(self, mock_compare):
        """Verify that constant-time compare_digest is invoked on valid inputs."""
        result = OTP_Generator.verify_otp("123456", "123456")
        self.assertTrue(result)
        mock_compare.assert_called_once_with("123456", "123456")


class TestCLIIntegration(unittest.TestCase):
    """Test suite covering interactive CLI behavior, prompts, and signal handling."""

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", return_value="654321")
    def test_cli_successful_verification(self, mock_input, mock_gen):
        """Entering matching OTP results in success message and return code 0."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Authentication successful: OTP verified.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", return_value="  654321  ")
    def test_cli_whitespace_trimmed_successfully(self, mock_input, mock_gen):
        """Leading and trailing whitespace on valid input should be trimmed."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Authentication successful: OTP verified.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", return_value="111111")
    def test_cli_incorrect_otp_failure(self, mock_input, mock_gen):
        """Entering mismatched OTP results in failure message and return code 1."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 1)
            self.assertIn("Authentication failed: Incorrect OTP.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", return_value="")
    def test_cli_empty_input_failure(self, mock_input, mock_gen):
        """Submitting empty input results in explicit error and return code 1."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 1)
            self.assertIn("Authentication failed: OTP cannot be empty.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", return_value="12abc3")
    def test_cli_non_numeric_input_failure(self, mock_input, mock_gen):
        """Submitting non-numeric characters results in format error and return code 1."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 1)
            self.assertIn("OTP must contain numeric digits (0-9) only.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", return_value="12345")
    def test_cli_incorrect_length_failure(self, mock_input, mock_gen):
        """Submitting wrong digit length results in length error and return code 1."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 1)
            self.assertIn("Expected 6 digits, but received 5.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", side_effect=KeyboardInterrupt)
    def test_cli_keyboard_interrupt_graceful_exit(self, mock_input, mock_gen):
        """Ctrl+C should be caught gracefully without uncaught stack traces."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Operation cancelled by user. Exiting cleanly.", output)

    @patch("OTP_Generator.generate_otp", return_value="654321")
    @patch("builtins.input", side_effect=EOFError)
    def test_cli_eof_graceful_exit(self, mock_input, mock_gen):
        """Ctrl+D / EOF should be caught gracefully without uncaught stack traces."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            exit_code = OTP_Generator.run_cli()
            output = mock_stdout.getvalue()

            self.assertEqual(exit_code, 0)
            self.assertIn("Operation cancelled by user. Exiting cleanly.", output)


if __name__ == "__main__":
    unittest.main()
