.PHONY: help test run clean

help:
	@echo "Available commands:"
	@echo "  make test   Run the complete automated test suite"
	@echo "  make run    Launch OTP Generator CLI (OTP_Generator.py)"
	@echo "  make clean  Clean compiled bytecode and temporary artifacts"

test:
	python3 -m unittest discover tests -v

run:
	python3 OTP_Generator.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

