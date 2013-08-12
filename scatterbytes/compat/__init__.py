"""compatability between supported Python versions

"""

try:
    from collections import OrderedDict
except:
    from .ordereddict import OrderedDict
