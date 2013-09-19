
__version__ = '0.9.11'

import logging

# used for server logging
logging.addLevelName(19, 'REQUEST')

# Clean up namespace.
del logging 


