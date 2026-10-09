"""Global pytest fixtures and test configuration."""

import pytest

from pktanalyzer.config.settings import AnalyzerSettings


@pytest.fixture
def custom_settings() -> AnalyzerSettings:
    """Fixture providing custom AnalyzerSettings for testing."""
    return AnalyzerSettings(
        environment="test",
        debug=True,
        dns_entropy_threshold=3.5,
        port_scan_threshold=10,
    )
