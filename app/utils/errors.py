"""Errors tailored for this project.

This module provides:
- UserNotFoundError: An error if a user or bot was not found
- ResourceNotFoundError: An error if a paste or another resource is not found
- ExpirationError: An error if a paste, a bot, or a token expired
- ConflictError: An error if a user or a paste already exists
- CredentialsError: An error if credentials are invalid. Who could've thought?
"""


class UserNotFoundError(LookupError):
    """A user or bot was not found."""

class ResourceNotFoundError(LookupError):
    """A paste or another resource was not found."""

class ExpirationError(TimeoutError):
    """A paste, a bot, or a token expired."""

class ConflictError(RuntimeError):
    """A user or a paste already exists."""

class CredentialsError(ValueError):
    """Credentials are invalid."""