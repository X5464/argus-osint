"""Shared wordlist resolution and password iteration for crack tools."""

import os

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_LINE_COUNT_CACHE = {}


def get_default_wordlist_path():
    """Return the first available rockyou wordlist path, or None."""
    candidates = [
        os.path.join(_PROJECT_ROOT, 'rockyou.txt'),
        os.path.join(_PROJECT_ROOT, 'data', 'wordlists', 'rockyou.txt'),
    ]
    for path in candidates:
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return os.path.abspath(path)
    return None


def resolve_wordlist(custom_path=None):
    """Return a valid wordlist path: custom if provided, else default rockyou."""
    if custom_path:
        candidate = os.path.expanduser(str(custom_path).strip())
        if not os.path.isabs(candidate):
            candidate = os.path.join(_PROJECT_ROOT, candidate)
        if os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
            return os.path.abspath(candidate)
        raise FileNotFoundError(f"Wordlist not found: {candidate}")

    default = get_default_wordlist_path()
    if not default:
        raise FileNotFoundError(
            "No wordlist found. Place rockyou.txt in the project root or data/wordlists/."
        )
    return default


# Backward-compatible alias
resolve_wordlist_path = resolve_wordlist


def get_wordlist_info(path=None):
    """Return name, path, line_count estimate, and size_mb for a wordlist."""
    try:
        wl_path = resolve_wordlist(path)
    except FileNotFoundError:
        return {
            'available': False,
            'name': 'none',
            'path': None,
            'line_count': 0,
            'entries': 0,
            'size_mb': 0.0,
        }

    size_bytes = os.path.getsize(wl_path)
    line_count = count_wordlist_lines(wl_path)
    return {
        'available': True,
        'name': os.path.basename(wl_path),
        'path': wl_path,
        'line_count': line_count,
        'entries': line_count,
        'size_mb': round(size_bytes / (1024 * 1024), 2),
    }


def wordlist_summary(path=None):
    """Metadata bundle for API/CLI responses (backward compatible)."""
    return get_wordlist_info(path)


def wordlist_display_name(path=None):
    """Short display name for UI/CLI output."""
    info = get_wordlist_info(path)
    return info['name'] if info['available'] else 'none'


def iter_passwords(path=None):
    """Yield passwords from a wordlist using latin-1 encoding."""
    wl_path = resolve_wordlist(path)
    with open(wl_path, 'r', encoding='latin-1', errors='ignore') as handle:
        for line in handle:
            password = line.rstrip('\r\n')
            if password:
                yield password


# Backward-compatible alias
iter_wordlist = iter_passwords


def count_wordlist_lines(path=None):
    """Count entries in a wordlist (cached after first read)."""
    wl_path = resolve_wordlist(path) if path else get_default_wordlist_path()
    if not wl_path:
        return 0

    if wl_path in _LINE_COUNT_CACHE:
        return _LINE_COUNT_CACHE[wl_path]

    count = 0
    with open(wl_path, 'r', encoding='latin-1', errors='ignore') as handle:
        for _ in handle:
            count += 1
    _LINE_COUNT_CACHE[wl_path] = count
    return count
