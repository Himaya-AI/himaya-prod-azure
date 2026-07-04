"""
CSPM plugin registry.

Each module under here registers a list of (PluginMeta, run_fn) tuples for one
cloud. The top-level functions below return the plugin set for engine consumption.
"""
from .azure import AZURE_PLUGINS
from .oracle import ORACLE_PLUGINS
from .github import GITHUB_PLUGINS
from .aws import AWS_PLUGINS
from .gcp import GCP_PLUGINS

__all__ = ["AZURE_PLUGINS", "ORACLE_PLUGINS", "GITHUB_PLUGINS", "AWS_PLUGINS", "GCP_PLUGINS"]
