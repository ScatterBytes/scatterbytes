import logging
from ..util import setup_logging
from ..jsonrpc import ControlNodeProxy
from ..jsonrpc import gen_storage_node_proxy_creator
from .node import ClientNode, ClientNodeConfig

logger = logging.getLogger(__name__)


def create_client_node(control_node_proxy=None,
                       storage_node_proxy_creator=None, config=None,
                       verbosity=None):
    """ClientNode Factory"""
    if config is None:
        config = ClientNodeConfig()
    setup_logging(config, stdout=True, verbosity=verbosity)
    if control_node_proxy is None:
        logger.debug('setting up control node proxy')
        control_node_proxy = ControlNodeProxy(config)
    if storage_node_proxy_creator is None:
        storage_node_proxy_creator = gen_storage_node_proxy_creator(config)
    return ClientNode(control_node_proxy, storage_node_proxy_creator, config)
