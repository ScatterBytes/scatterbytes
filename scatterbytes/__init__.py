
__version__ = '0.9.9'

import logging

# used for server logging
logging.addLevelName(19, 'REQUEST')

# Clean up namespace.
del logging 


