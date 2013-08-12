"""common configuration functionality

Contains the functionality shared by the ClientNodeConfig and
StorageNodeConfig.

"""
from __future__ import with_statement

import os
import sys
import shutil
import logging
import tempfile
import threading
import ConfigParser
from .errors import ConfigError

logger = logging.getLogger(__name__)

# Are we testing?

TESTING = 'SB_TESTING' in os.environ

# Disabled for some testing.
FSYNC_ON_SAVE=True

# Setting this will affect where data and config files are read/written to.
# This was created for testing.
DATA_DIRECTORY = None

# Proper Unix Directories - If not available, use home directory.

class ConfigBase(object):

    """base class for storage and client node configs

    config_path
        full path to config file

    """

    sections = ['main', 'network', 'notification']

    if TESTING:
        defaults = {
            'node_id' : ('main', '', None),
            'control_node_address' : \
                        ('network', 'controlnode.test.scatterbytes.net', None),
            'control_node_port' : ('network', 8080, 'int'),
            'debug' : ('main', True, 'boolean'),
        }
    else:
        defaults = {
            'node_id' : ('main', '', None),
            'control_node_address' : \
                        ('network', 'controlnode.scatterbytes.net', None),
            'control_node_port' : ('network', 8080, 'int'),
            'debug' : ('main', False, 'boolean'),
        }
    # check environment variables
    v = 'SB_CONTROLNODE_HOST'
    if v in os.environ:
        defaults['control_node_address'] = ('network', os.environ.get(v), None)
    del v

    main_section = 'main'
    cached_config = None
    # directories to search for configs in
    search_dirs = None

    def __init__(self, config_path=None, use_config_paths=False):
        """

        config_path
            location of the config file

        use_config_paths
            Use this config directory for all path settings instead of
            attempting to locate a conventional path.

        """

        self.use_config_paths = use_config_paths
        if config_path is None:
            config_dir = self.find_config_dir()
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, 0700)
            config_path = os.path.join(config_dir, self.config_name)
        self.modified = False
        parser = ConfigParser.SafeConfigParser()
        self.config_path = config_path
        self.parser = parser
        self.modified = False
        self.lock = threading.RLock()
        self.read()
        # set the defaults if need be
        for section in self.sections:
            if not parser.has_section(section):
                parser.add_section(section)
                self.modified = True
        section = self.main_section
        self.modified = True
        self._setting_defaults = True
        for key in self.defaults:
            (df_section, df_value, df_type) = self.defaults[key]
            if not parser.has_option(df_section, key):
                self.modified = True
                self.set(key, df_value, section=df_section)
        self._setting_defaults = False
        config_dir = os.path.dirname(config_path)
        section = self.main_section
        if not parser.has_option(section, 'ssl_dir'):
            ssl_dir = os.path.join(config_dir, 'ssl')
            if not os.path.exists(ssl_dir):
                os.makedirs(ssl_dir, 0700)
            self.set('ssl_dir', ssl_dir)
            self.modified = True
        if not parser.has_option(section, 'log_dir'):
            if self.use_config_paths:
                log_dir = os.path.join(config_dir, 'logs')
            else:
                log_dir = find_log_dir()
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            self.set('log_dir', log_dir)
            self.modified = True
        self._init_prep()
        if self.modified:
            self.save()

    @property
    def mtime(self):
        return os.stat(self.config_path).st_mtime

    def init_prep(self):
        pass

    def _init_prep(self):
        from . import crypt
        if not os.path.exists(self.ca_root_cert_path):
            logger.info('Writing Root CA Cert')
            open(self.ca_root_cert_path, 'wb').write(CA_ROOT_CERT_PEM)
        if not os.path.exists(self.private_key_path):
            crypt.create_pkey(output_path=self.private_key_path)
            logger.info('Creating RSA Key at %s' % self.private_key_path)
        self.init_prep()

    @classmethod
    def get_config(cls):
        config_dir = cls.find_config_dir()
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
        config_path = os.path.join(config_dir, cls.config_name)
        config = cls(config_path)
        return config

    def read(self):
        with self.lock:
            if os.path.exists(self.config_path):
                self.parser.read(self.config_path)

    def save(self):
        with self.lock:
            if not FSYNC_ON_SAVE:
                f = open(self.config_path, 'wb')
                self.parser.write(f)
                f.close()
                return
            (f, file_path) = tempfile.mkstemp(prefix='scatterbytes_')
            try:
                f = open(file_path, 'wb')
                self.parser.write(f)
                f.flush()
                os.fsync(f.fileno())
                f.close()
                shutil.move(file_path, self.config_path)
            except:
                if os.path.exists(file_path):
                    os.unlink(file_path)
                raise
            self.modified = False

    def get(self, key, raw=False, section=None):
        if section is None:
            section = self.main_section
        with self.lock:
            parser = self.parser
            if hasattr(self, '_get_' + key):
                return getattr(self, '_get_' + key)()
            if key in self.defaults and self.defaults[key][2]:
                method_name = 'get' + self.defaults[key][2]
                return getattr(parser, method_name)(section, key)
            else:
                try:
                    value = self.parser.get(section, key, raw=raw)
                except ConfigParser.NoOptionError:
                    return None
            return value

    def set(self, key, value, section=None):
        if section is None:
            section = self.main_section
        with self.lock:
            self.modified = True
            parser = self.parser
            if hasattr(self, '_set_' + key):
                return getattr(self, '_set_' + key)(value)
            return parser.set(section, key, str(value))

    # for convenience
    @property
    def data_directory(self):
        dd = self.get('data_directory')
        if not dd:
            return os.path.dirname(self.config_path)
        return dd

    @data_directory.setter
    def data_directory(self, value):
        # make sure it exists
        assert os.path.exists(value), '%s does not exist' % value
        self.set('data_directory', value)

    @property
    def log_path(self):
        log_dir = self.get('log_dir')
        if log_dir:
            return os.path.join(log_dir, self.log_filename)

    @property
    def private_key_path(self):
        key_name = '%s_key.pem' % self.config_name.split('.')[0]
        return os.path.join(self.get('ssl_dir'), key_name)

    @property
    def ca_root_cert_path(self):
        return os.path.join(self.get('ssl_dir'), 'ca_root_cert.pem')

    @property
    def cert_path(self):
        cert_name = '%s_cert.pem'%self.config_name.split('.')[0]
        return os.path.join(self.get('ssl_dir'), cert_name)

    @property
    def certificate(self):
        from . import crypt
        return crypt.Certificate(self.cert_path)

    @property
    def cert_info(self):
        return self.certificate.info

    def make_ssl_context(self):
        "create an M2Crypto.SSL.Context"
        # somewhat of a hack
        if self.__class__.__name__ == 'ClientNodeConfig':
            ctx_type = 'client'
        else:
            ctx_type = 'server'
        if not os.path.exists(self.cert_path):
            ctx_type = 'init'
        # delay import to prevent circular import
        from . import crypt
        return crypt.make_context(self.ca_root_cert_path, self.cert_path,
                                  self.private_key_path, mode=ctx_type)

    @classmethod
    def find_config_dir(cls):
        return find_config_dir(
            search_dirs=cls.search_dirs, config_name=cls.config_name
        )

    @classmethod
    def find_config_path(cls):
        return os.path.join(cls.find_config_dir(), cls.config_name)

CA_ROOT_CERT_PEM = """
-----BEGIN CERTIFICATE-----
MIIC7TCCAdWgAwIBAgIBATANBgkqhkiG9w0BAQUFADAxMRAwDgYDVQQDEwdSb290
IENBMR0wGwYDVQQKExRTY2F0dGVyQnl0ZXMgTmV0d29yazAeFw0xMjAxMjAxNTA0
MTNaFw0zNzAxMTMxNTA0MTNaMDExEDAOBgNVBAMTB1Jvb3QgQ0ExHTAbBgNVBAoT
FFNjYXR0ZXJCeXRlcyBOZXR3b3JrMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEApb0M5hjLcWAt59KlyIKDrqGelrvzpH4+VW6Zqx2jqGAaMJ4uwupXuRAN
JBckHDbIZkCoBAC2edUngx8Zmbjud0EoH2nWuibWALrw/FdwYC8TMhSfwF1a7+5N
go0S7ZUKWemDl4oIDWEGPb0eIBDKujq+gsHFj9T9XEtz+zhgthqGld8SVVl6zIaJ
J54H7oslTWl23tXw0eir0uJMQqlJK2hBSzlvOBgdwKlrc8B4YJgXOH5jz0+jPuZx
vaW78wZy0WmzMv5UNg6fbghTsduMuchrBY49cGc4390hFvleoFWpBnr3D0InKqn9
5pgzX1hxx9OWC6X0F/fWHtK9nfskawIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0G
CSqGSIb3DQEBBQUAA4IBAQA1Icz1s2OgQcgXaG2qpFZYUbSjw2lbNn7JfcfiDL2A
+Y585xXMZXq482LPxkj7MxaOEY3LPIAK1mp6CD/cmbL8ZkAKgUWQnNQreCvI6wnk
WP3Amg3zYBT1puSL/FT9nF1HQ0lKu8WM6Zw+6EPc+MHw2dE0dZRvzcyvge6aiYhs
zFYTiqeEKuS8et5+8IFqQ97pH55dX8/xocsGoJuAPO+4JTrT7GdQkBB1tAL3hhbJ
cOgLVWbW40a9JXVNr+iiIKgP7oWCbpgnfkaWXSOYSOR5zTwbPG8e/wYyi8M1Ujl/
XIUOqvFRY63WUKL3DfGY+bKPPgBbi4bBxHc3UCFI5kwE
-----END CERTIFICATE-----
"""

if 'SB_ROOT_CERT_PATH' in os.environ:
    CA_ROOT_CERT_PEM = open(os.environ['SB_ROOT_CERT_PATH']).read()


def find_home_dir():
    if sys.platform.startswith('win'):
        home = os.environ.get('HOMEPATH', None)
        if not home:
            home = os.path.expanduser('~')
    else:
        home = os.path.expanduser('~')
    if not home:
        raise ConfigError("can't find home")
    return home

def find_data_dir():
    """Find the directory to write data to.

    This is a default which can be overwritten in the config.

    """

    if DATA_DIRECTORY and os.path.exists(DATA_DIRECTORY):
        logger.debug('DATA_DIRECTORY is %s' % DATA_DIRECTORY)
        return DATA_DIRECTORY
    if sys.platform.startswith('win'):
        app_data = os.environ.get('APPDATA', None)
        if not app_data:
            app_data == find_home_dir()
        sb_dir = os.path.join(app_data, 'ScatterBytes')
    else:
        if is_sb_user():
            sb_dir = find_home_dir()
        else:
            sb_dir = os.path.join(
                find_home_dir(), '.local', 'share', 'scatterbytes'
            )
    if not sb_dir:
        raise ConfigError("can't find application data directory")
    return sb_dir

def is_sb_user():
    "is this a dedicated scatterbytes user?"
    # if so, there is no need for a namespace such as .config/scatterbytes
    home_dir = find_home_dir()
    has_access = os.access(home_dir, os.W_OK)
    if home_dir and home_dir.lower().endswith('scatterbytes') and has_access:
        return True
    return False

def find_log_dir():
    """Find the directory to write logs to.

    This is a default which can be overwritten in the config.

    """

    if DATA_DIRECTORY and os.path.exists(DATA_DIRECTORY):
        logger.debug('DATA_DIRECTORY is %s' % DATA_DIRECTORY)
        return DATA_DIRECTORY
    if sys.platform.startswith('win'):
        app_data = os.environ.get('APPDATA', None)
        if not app_data:
            app_data == find_home_dir()
        sb_dir = os.path.join(
            app_data, 'ScatterBytes', 'Logs'
        )
    else:
        if is_sb_user():
            sb_dir = os.path.join(find_home_dir(), 'logs')
        else:
            sb_dir = os.path.join(
                find_home_dir(), '.cache', 'scatterbytes', 'logs'
            )
    if not sb_dir:
        raise ConfigError("can't find log directory")
    return sb_dir

def find_config_dir(search_dirs=None, config_name=None):
    if DATA_DIRECTORY and os.path.exists(DATA_DIRECTORY):
        logger.debug('DATA_DIRECTORY is %s' % DATA_DIRECTORY)
        return DATA_DIRECTORY
    elif search_dirs:
        sb_dir = None
        for search_dir in search_dirs:
            config_path = os.path.join(search_dir, config_name)
            if os.path.exists(config_path):
                return search_dir
    if sys.platform.startswith('win'):
        app_data = os.environ.get('APPDATA', None)
        if not app_data:
            app_data == find_home_dir()
        sb_dir = os.path.join(app_data, 'ScatterBytes')
    else:
        # if name == scatterbytes, no need for namespace
        if is_sb_user():
            sb_dir = find_home_dir()
        else:
            sb_dir = os.path.join(find_home_dir(), '.config', 'scatterbytes')
    if not sb_dir:
        raise ConfigError("can't find application data directory")
    return sb_dir
