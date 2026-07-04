"""Per-cloud DSPM scanners."""
from .aws_s3 import scan_aws_s3, AWSS3ScanConfig
from .azure_blob import scan_azure_blob, AzureBlobDSPMConfig
from .gcp_gcs import scan_gcs, GCSDSPMConfig
from .m365_graph import scan_m365, M365DSPMConfig

__all__ = [
    "scan_aws_s3",
    "AWSS3ScanConfig",
    "scan_azure_blob",
    "AzureBlobDSPMConfig",
    "scan_gcs",
    "GCSDSPMConfig",
    "scan_m365",
    "M365DSPMConfig",
]
