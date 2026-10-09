"""Core exceptions for Packet Analyzer engine."""


class PCAPError(Exception):
    """Base exception for PCAP operations."""


class PCAPFormatError(PCAPError):
    """Raised when file format is not a recognized PCAP."""


class PCAPCorruptError(PCAPError):
    """Raised when packet record header or data is truncated/corrupt."""
