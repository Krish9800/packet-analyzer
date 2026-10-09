"""Unit tests for foundational project configuration and settings."""

from pktanalyzer import __version__
from pktanalyzer.config.settings import AnalyzerSettings, get_settings


def test_version() -> None:
    """Verify package version is defined."""
    assert __version__ == "0.1.0"


def test_default_settings() -> None:
    """Verify default settings instantiation and types."""
    settings = get_settings()
    assert settings.app_name == "Packet Analyzer"
    assert settings.api_port == 8084
    assert settings.dns_entropy_threshold == 3.8
    assert settings.max_pcap_size_bytes == 104857600
    assert not settings.debug


def test_custom_settings(custom_settings: AnalyzerSettings) -> None:
    """Verify overridden settings via fixture."""
    assert custom_settings.environment == "test"
    assert custom_settings.debug is True
    assert custom_settings.dns_entropy_threshold == 3.5
    assert custom_settings.port_scan_threshold == 10
