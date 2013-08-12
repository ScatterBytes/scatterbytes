"""common node testing functionality

"""

import os
import shutil
from ..client.node import ClientNodeConfig
from ..storage.node import StorageNodeConfig
from . import util as test_util
from . import ssl


def get_config_dir(node_id, node_type):
    config_dir = os.path.join(
        test_util.TEST_DIR, '%s_nodes' % node_type, node_id
    )
    return config_dir

def prepare_config(node_id, node_type='storage'):
    """Create default config in test location based on node_id.

    """
    if node_type == 'client':
        config_class = ClientNodeConfig
    else:
        config_class = StorageNodeConfig
    config_path = os.path.join(get_config_dir(node_id, node_type),
                               config_class.config_name)
    config = config_class(config_path=config_path)
    config.set('node_id', node_id)
    config.set('recert_code', 'XYZ')
    return config

def prepare_ssl(node_id, node_type='storage', initialize=False):
    """Download necessary certificates and optionally generate a key. 

    Normally, a client will create it's own key and obtain a signed
    certificate from the control node.  For testing purposes, which
    initialize=True, generate a private key and signed certificate without
    requiring the node to request it.

    """
    # Just need the root ca cert to start with.
    ssl_dir = ssl.get_ssl_dir()
    config_dir = get_config_dir(node_id, node_type)
    node_ssl_dir = os.path.join(config_dir, 'ssl')
    shutil.copy2(
        os.path.join(ssl_dir, 'ca_root', 'cert.pem'),
        os.path.join(node_ssl_dir, 'ca_root_cert.pem')
    )
    if initialize:
        # download certs, generate private key and cert
        shutil.copy2(
            os.path.join(ssl_dir, 'software_signer', 'cert.pem'),
            os.path.join(node_ssl_dir, 'software_signer_cert.pem')
        )
        shutil.copy2(
            os.path.join(ssl_dir, 'relay_command_signer', 'cert.pem'),
            os.path.join(node_ssl_dir, 'relay_command_signer_cert.pem')
        )
        # generate if they're not created yet
        ssl.gen_ssl_node(node_id)
        pkey_src_path = ssl.get_key_path(owner_name=node_id)
        key_name = '%s_node_key.pem' % node_type
        pkey_tgt_path = os.path.join(node_ssl_dir, key_name)
        shutil.copy2(pkey_src_path, pkey_tgt_path)
        cert_src_path = ssl.get_cert_path(owner_name=node_id)
        cert_tgt_path = os.path.join(
            node_ssl_dir, '%s_node_cert.pem' % node_type
        )
        shutil.copy2(cert_src_path, cert_tgt_path)

def prepare_node(node_id, node_type='storage', initialize=False):
    "combine prepare_config with prepare_ssl"
    config = prepare_config(node_id, node_type)
    prepare_ssl(node_id, node_type, initialize)
    return config

def create_storage_node_configs(storage_nodes, config_dir):
    for storage_node in storage_nodes:
        node_id = storage_node.id
        node_config_dir = os.path.join(config_dir, str(node_id).zfill(5))
        if not os.path.exists(node_config_dir):
            os.mkdir(node_config_dir)
        config_path = os.path.join(node_config_dir,
                                            StorageNodeConfig.config_name)
        conf = StorageNodeConfig(config_path=config_path)
        conf.auth_key = storage_node.auth_key
        conf.set('listen_port', storage_node.port)
        conf.set('central_node_address', '10.2.0.1')
        conf.set('node_id', storage_node.id)
        conf.save()
