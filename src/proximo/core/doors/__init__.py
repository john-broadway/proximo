"""Doors onto the governed core. A door carries requests; it never decides them."""

# The banner, ONCE. John, 2026-09-26: HIS pick, draft A -- block letters, no door image, and
# under them the line he still loves, in his own rendering, centred. `packaging/lxc/ct/
# proximo.sh` carries the same bytes in a heredoc (bash cannot import); tests/test_banner.py
# holds the two copies together. RAW: rows end in a backslash, which a plain string reads as
# a continuation.
BANNER = r""" ____                _
|  _ \ _ __ _____  _(_)_ __ ___   ___
| |_) | '__/ _ \ \/ / | '_ ` _ \ / _ \
|  __/| | | (_) >  <| | | | | | | (_) |
|_|   |_|  \___/_/\_\_|_| |_| |_|\___/
    Win the crowd, Win your freedom
"""
