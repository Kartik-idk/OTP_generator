# Contributing to OTP Generator

Thank you for your interest in improving the **OTP Generator** project!

## Development Guidelines

1. **Follow PEP 8**: Ensure your code conforms to Python's PEP 8 style guide.
2. **Standard Library Only**: Do not introduce external dependencies without prior discussion. The project aims for zero external dependencies.
3. **Cryptographic Integrity**: Always use cryptographically secure random number generation (`secrets` module) and constant-time string comparisons (`secrets.compare_digest`). Never substitute with pseudo-random generators (`random` module).
4. **Automated Testing**: Add or update unit tests in `tests/test_otp_generator.py` for any bug fix or feature addition. All tests must pass before submitting a pull request.
5. **No Broken Signals**: Ensure terminal interrupts (`KeyboardInterrupt`, `EOFError`) continue to exit cleanly.

## Running Tests

Execute the complete test suite locally:
```bash
make test
# or
python3 -m unittest discover tests -v
```

## Submitting Pull Requests

1. Fork the repository and create your feature branch: `git checkout -b feature/my-feature`.
2. Commit your changes with clear, descriptive commit messages.
3. Verify all tests pass and no temporary files are tracked.
4. Push to your fork and submit a Pull Request describing your changes.

