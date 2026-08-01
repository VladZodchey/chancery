import secrets

# URL-safe alphabet with ambiguous characters (0/O, 1/l/I) removed.
_ALPHABET = "23456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"


def new_id(length: int) -> str:
    """Generate an unguessable paste id (58^length possibilities)."""
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))
