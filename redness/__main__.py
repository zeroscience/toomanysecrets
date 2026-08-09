"""Entrypoint so `python -m redness` and the frozen redness.exe share one path."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
