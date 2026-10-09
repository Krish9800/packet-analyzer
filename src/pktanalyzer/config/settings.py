"""Configuration settings for Packet Analyzer."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class AnalyzerSettings(BaseSettings):
    """Runtime configuration for Packet Analyzer engine, detection, and API."""

    model_config = SettingsConfigDict(
        env_prefix="PKTANALYZER_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "Packet Analyzer"
    version: str = "0.1.0"
    environment: str = "production"
    debug: bool = False

    # Server settings
    api_host: str = "0.0.0.0"  # nosec B104
    api_port: int = 8084

    # Processing bounds
    max_pcap_size_bytes: int = 100 * 1024 * 1024  # 100 MB max capture upload
    max_packets_to_process: int = 500_000

    # Detection parameters
    dns_entropy_threshold: float = 3.8
    port_scan_threshold: int = 15
    port_scan_window_seconds: float = 5.0
    arp_cache_timeout_seconds: float = 300.0
    reassembly_timeout_seconds: float = 60.0
    max_stream_buffer_bytes: int = 10 * 1024 * 1024  # 10 MB per stream


@lru_cache(maxsize=1)
def get_settings() -> AnalyzerSettings:
    """Return cached instance of AnalyzerSettings."""
    return AnalyzerSettings()
