#!/usr/bin/env python

import re

# run this from the project root

def main():
    # change version numbers
    version = open('VERSION').read().strip()
    print 'new version is %s' % version
    # module init file
    version_files = [
        (   
            'scripts/sbnet',
            [re.compile(r"^(__version__ = ')(\d+\.\d+\.\d+)('\n)"),]
        ),
        (   
            'scatterbytes/__init__.py',
            [re.compile(r"^(__version__ = ')(\d+\.\d+\.\d+)('\n)"),]
        ),
        (
            'setup.py',
            [re.compile(r"^(VERSION = ')(\d+\.\d+\.\d+)('\n)"),]
        ),
        (
            'docs/conf.py',
            [re.compile(r"^(version = ')(\d+\.\d+)('\n)"),
             re.compile(r"^(release = ')(\d+\.\d+\.\d+)('\n)")]
        )
    ]
    for (fname, regexes) in version_files:
        lines = open(fname, 'rb').readlines()
        new_lines =  lines[:]
        for (i, l) in enumerate(lines):
            for regex in regexes:
                match = regex.match(l)
                if match:
                    print 'changed %s' % fname
                    g = match.groups()
                    v = version
                    if len(match.groups()[1].split('.')) < 3:
                        # use the short version
                        v = '.'.join(v.split('.')[0:2])
                    new_lines[i] = ''.join("%s%s%s" % (g[0], v, g[2]))
        open(fname, 'wb').write(''.join(new_lines))

if __name__ == '__main__':
    main()
