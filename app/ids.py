"""A module for handling unique ID generation."""
from threading import Lock
from time import time
from secrets import randbits


class Generator:
    """A class that spits out unique IDs."""
    def __init__(self):
        self.sequence = 0
        self.last_timestamp = 0
        self.lock = Lock()

    def generate_id(self) -> int:
        """Generates a 64-bit Snowflake-like ID.

        Returns:
            int: The ID
        """
        with self.lock:
            timestamp = int(time() * 1000)
            if timestamp == self.last_timestamp:
                self.sequence += 1
            else:
                self.sequence = 0
                self.last_timestamp = timestamp
            random_bits = randbits(16)
            return (timestamp << 32) | (random_bits << 16) | (self.sequence & 0xFFFF)