"""Entry point for the Cytadel Exposure Assessment GUI."""

import sys

from cytadel.ui import run_app


def main() -> int:
    return run_app()


if __name__ == "__main__":
    sys.exit(main())
