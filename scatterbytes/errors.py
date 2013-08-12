"""error classes used by this package.

"""

def format_exc(e):
    if isinstance(e, Exception):
        name = e.__class__.__name__
        msg = '%s: %s' % (name, str(e))
    else:
        msg = str(e)
    return msg

class SBError(Exception): pass

class SBValueError(ValueError, SBError): pass

class RequestExpiredError(SBError): pass

class StaleCommandRelayError(SBError): pass

class ConfigError(SBError): pass

class ClientNotFoundError(SBError): pass

class ChecksumError(SBError):
    """error checksumming file
    
    used for disk and transmission related errors

    """
    pass

class SecureHashError(SBError):
    """secure hash check failed
    
    used when comparison against secure hash (SHA-2) fails
    
    """
    pass

class DuplicateFilenameError(SBError): pass

class FileNotFoundError(SBError): pass

class FileExistsError(SBError): pass

class VolumeNotFoundError(SBError): pass

class OutOfStorageError(SBError): pass

class InsufficientStorageError(SBError): pass

class ChunkError(SBError):
    """related to file chunks"""
    pass

class ChunkNotFoundError(ChunkError): pass

class ChunkChecksumError(ChunkError, ChecksumError):
    """checksuming chunk failed"""
    pass

class DownloadError(SBError): pass

class UpdateError(SBError): pass

class EncryptionError(SBError): pass

class TransferLogError(SBError):
    """error related to download or upload log"""
    pass

class AuthenticationError(SBError): pass

class CertificateError(SBError): pass

class CRLError(SBError): pass

class CertificateRequestError(SBError): pass
