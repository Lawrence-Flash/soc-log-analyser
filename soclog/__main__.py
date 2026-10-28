"""Allow `python3 -m soclog`."""

import sys

from soclog.cli import main

if __name__ == "__main__":
    sys.exit(main())
