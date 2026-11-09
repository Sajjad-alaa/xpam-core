__version__ = '0.0.59'

from .ftp import FTPStorage
from .s3 import S3Storage
from .azure import AzureStorage
from .ceph import CEPHStorage
from .jms import JMSReplayStorage, JMSCommandStorage
from .multi import MultiObjectStorage
from .sftp import SFTPStorage


def get_object_storage(config):
    if config.get("TYPE") in ["s3", "ceph", "swift"]:
        return S3Storage(config)
    elif config.get("TYPE") == "server":
        return JMSReplayStorage(config)
    elif config.get("TYPE") == "azure":
        return AzureStorage(config)
    elif config.get("TYPE") == "ceph":
        return CEPHStorage(config)
    elif config.get("TYPE") == "ftp":
        return FTPStorage(config)
    elif config.get("TYPE") == "sftp":
        return SFTPStorage(config)
    else:
        return JMSReplayStorage(config)


def get_multi_object_storage(configs):
    return MultiObjectStorage(configs)

