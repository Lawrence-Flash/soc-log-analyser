"""Log parsers and format detection."""

from soclog.parsers.detect import FORMATS, detect_format
from soclog.parsers.linux_auth import parse_linux_auth
from soclog.parsers.web_access import parse_web_access
from soclog.parsers.windows import parse_windows_csv, parse_windows_json

PARSERS = {
    "linux-auth": parse_linux_auth,
    "web-access": parse_web_access,
    "windows-json": parse_windows_json,
    "windows-csv": parse_windows_csv,
}

__all__ = [
    "FORMATS",
    "PARSERS",
    "detect_format",
    "parse_linux_auth",
    "parse_web_access",
    "parse_windows_csv",
    "parse_windows_json",
]
