"""ScatterBytes Updates.

This module functions to update the scatterbytes package.

"""

import os
import re
import sys
import time
import urllib2
import logging
import datetime
from . import crypt
from . import config
from .errors import UpdateError

logger = logging.getLogger(__name__)


UPDATE_URL = os.environ.get('SB_UPDATE_URL') or \
                        'https://controlnode.scatterbytes.net:8080/updates'


# local cache
CACHE = {}
   

PROGRAM_RE = {
    'sbnet' : re.compile(r'^sbnet-(\d+.\d+.\d+)$'),
    'scatterbytes-package' : re.compile(
        r'^scatterbytes-package-(\d+.\d+.\d+).zip$'
    )
}
TS_FORMAT = '%Y-%m-%dT%H:%M:%S'
CHECK_LOG_NAME = 'scatterbytes_package_check.txt'


def find_home_dir(use_cache=True):
    if use_cache and 'home_dir' in CACHE:
        return CACHE['home_dir']
    home = config.find_home_dir()
    CACHE['home_dir'] = home
    return home


def find_data_dir(use_cache=True):
    """Find the directory to write package to.
    
    """

    if use_cache and 'data_dir' in CACHE:
        return CACHE['data_dir']
    sb_dir = config.find_data_dir()
    # Need this directory if it doesn't exist yet.
    if not os.path.exists(sb_dir):
        os.makedirs(sb_dir)
    CACHE['data_dir'] = sb_dir
    return sb_dir


def find_package_path():
    data_dir = find_data_dir()
    package_names = []
    for f in os.listdir(data_dir):
        match = PROGRAM_RE['scatterbytes-package'].match(f)
        if match:
            package_names.append(f)
    if package_names:
        package_names.sort()
        package_name = package_names[-1]
        package_path = os.path.join(data_dir, package_name)
        return package_path


def check_update_period(minutes=60):
    """Check if an update has been attempted within specified period."""

    current_time = datetime.datetime.utcnow()
    data_dir = find_data_dir()
    check_log_path = os.path.join(data_dir, CHECK_LOG_NAME)
    if not os.path.exists(check_log_path):
        return False
    try:
        dt_text = open(check_log_path).read()
        t_struct = time.strptime(dt_text, TS_FORMAT)
        t_args = map(int, t_struct[:6])
        dt = datetime.datetime(*t_args)
        period = current_time - dt
        if period < datetime.timedelta(minutes=minutes):
            return True
        return False
    except:
        logger.error('check_log failed', exc_info=True)
        return False


def add_package_to_path(package_path=None):
    if package_path is None:
        package_path = find_package_path()
        assert package_path, 'no package found'
    if package_path not in sys.path:
        sys.path.insert(1, package_path)


def get_installed_sb_version():
    package_path = find_package_path()
    if package_path:
        match = PROGRAM_RE['scatterbytes-package'].match(package_path)
        if match:
            package_version = match.groups()[0]
            return package_version


def get_current_program_info(name):
    "grab the current package info from the update host"
    url = UPDATE_URL + '/%s.txt' % name
    f = urllib2.urlopen(url)
    program_text = f.read()
    (pgm_name, pgm_hash, pgm_sig) = program_text.split()
    pgm_version = PROGRAM_RE[name].match(pgm_name).groups()[0]
    return (pgm_name, pgm_version, pgm_hash, pgm_sig)


def check_cert_signature(cert_pem_string):
    """check that a certificate was signed by root cert"""
    cert = crypt.Certificate(pem_string=cert_pem_string)
    root_cert = crypt.Certificate(pem_string=config.CA_ROOT_CERT_PEM)
    cert.verify(root_cert.public_key)


def get_software_signer_cert():
    """get the certificate to check signature on new software"""
    url = UPDATE_URL + '/software_signer_cert.pem'
    cert_pem = urllib2.urlopen(url).read()
    check_cert_signature(cert_pem)
    return cert_pem


def update_check_log():
    """update log for program updates"""
    data_dir = find_data_dir()
    check_log_path = os.path.join(data_dir, CHECK_LOG_NAME)
    f = open(check_log_path, 'wb')
    f.write(datetime.datetime.utcnow().strftime(TS_FORMAT))
    f.close()


def get_updated_program(name, installed_version):
    """update scatterbytes packages or sbnet program"""
    import hashlib
    import binascii
    assert name in ('scatterbytes-package', 'sbnet')
    (pgm_name, pgm_version, pgm_hash, pgm_sig) = get_current_program_info(name)
    update_check_log()
    if pgm_version <= installed_version:
        return
    pgm_url = UPDATE_URL + '/' + pgm_name
    f = urllib2.urlopen(pgm_url)
    pgm_data = f.read()
    # check the hash
    calc_hash = hashlib.sha256(pgm_data).hexdigest()
    assert calc_hash == pgm_hash
    # check the signature on the hash
    cert = crypt.Certificate(pem_string=get_software_signer_cert())
    pubkey = cert.public_key
    pubkey.verify_init()
    pubkey.verify_update(calc_hash)
    pgm_sig_bin = binascii.unhexlify(pgm_sig)
    assert pubkey.verify_final(pgm_sig_bin) == 1, 'signature check failed'
    return (pgm_name, pgm_version, pgm_data)


def update_package(force=False, queue=None):
    # update scatterbytes package
    # return value of 1 means not updated
    # return value of 2 means updated
    ret = 1
    if not force and check_update_period():
        # skip if this was done recently
        if queue:
            queue.put(ret)
        return ret
    # scatterbytes package first
    try:
        sb_version = get_installed_sb_version()
        response = get_updated_program('scatterbytes-package', sb_version)
        if response:
            (package_name, package_version, package_data) = response
            # checks passed - save the program
            sb_path = os.path.join(find_data_dir(), package_name)
            open(sb_path, 'wb').write(package_data)
            logger.debug('got new package version %s' % package_version)
            # test it
            add_package_to_path(sb_path)
            try:
                reload_package()
                import scatterbytes.cli
                logger.debug('reloaded %s' % scatterbytes.cli)
            except:
                logger.error('new package failed - removing', exc_info=True)
                os.unlink(sb_path)
                sys.path.remove(sb_path)
            else:
                ret = 2
                if queue:
                    queue.put(ret)
                else:
                    return ret
    except:
        logger.error('error updating package', exc_info=True)


def update_all(force=False):
    # for now, just update the package
    # running in another process so modules don't get loaded in this namespace
    logger.debug('updating package')
    import Queue
    import multiprocessing
    queue = multiprocessing.Queue()
    p = multiprocessing.Process(target=update_package, args=(force, queue))
    p.start()
    p.join()
    try:
        queue.get(False)
    except Queue.Empty:
        raise UpdateError('Update failed! Check log for details.')
    logger.debug('updating finished')


def reload_package():
    """reload the scatterbytes package
    
    This is intended to be used after inserting a new package in sys.path.
    
    """
    reload_list = []
    for (k, m) in sys.modules.items():
        if k.startswith('scatterbytes') and m is not None:
            reload_list.append(m)
    # top must reload first
    reload_list.sort()
    for m in reload_list:
        logger.debug('reloading %s' % m)
        reload(m)
