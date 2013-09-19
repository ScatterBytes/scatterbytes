#!/usr/bin/env python

import os
import sys
from distutils.command.build_py import build_py
from setuptools import setup, find_packages

VERSION = '0.9.12'

class BuildZipPackage(build_py):
    description = "create zipped package signed and ready to run"

    def _sign(self, input_path, sig_path):
        import hashlib
        import binascii
        from M2Crypto import EVP
        key_path = os.environ.get('SB_SW_KEY')
        pkey = EVP.load_key(key_path)
        # Create a hash from the zip file and sign it.
        h = hashlib.new('sha256')
        h.update(open(input_path, 'rb').read())
        digest = h.hexdigest()
        pkey.sign_init()
        pkey.sign_update(digest)
        sig = binascii.hexlify(pkey.sign_final())
        #verify to make sure this was done right
        bsig = binascii.unhexlify(sig)
        pkey.verify_init()
        pkey.verify_update(digest)
        assert pkey.verify_final(bsig), 'signature not verified'
        f = open(sig_path, 'wb')
        f.write(os.path.basename(input_path) + '\n\n')
        f.write(digest + '\n\n')
        f.write(sig)
        f.close()

    def run(self):
        import shutil
        import zipfile
        build_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            'build'
        )
        self.build_lib = build_dir
        build_py.run(self)
        build_path = os.path.join(build_dir, 'scatterbytes')
        # remove unnecessary files
        shutil.rmtree(os.path.join(build_path, 'testing'))
        zip_path = build_path + '-package-%s.zip' % VERSION
        zf = zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED)
        for (dirpath, dirnames, filenames) in os.walk(build_path):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                arcname = filepath[len(build_dir):]
                zf.write(filepath, arcname)
        zf.close()
        sig_path = build_path + '-package.txt'
        self._sign(zip_path, sig_path)
        # cleanup
        shutil.rmtree(build_path)
        # copy sbnet script
        script_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), 'scripts', 'sbnet'
        ))
        for line in open(script_path):
            if line.strip().startswith('__version__'):
                version = line.split()[-1].strip("'")
                break
        output_path = os.path.join(
            build_dir, 'sbnet-%s' % version
        )
        shutil.copy2(script_path, output_path)
        sig_path = os.path.join(build_dir, 'sbnet.txt')
        self._sign(output_path, sig_path)


if sys.version_info[0] <> 2 or sys.version_info[1] not in (6, 7):
    print 'Python 2.6 or 2.7 is required'
    sys.exit(1)

install_requires=['formencode']
if sys.version_info < (2,7):
    install_requires.append('argparse>=1.1')
# Require daemon if this is a forking OS
try:
    os.fork
    install_requires.append('python-daemon')
except AttributeError:
    pass

classifiers = [
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'Intended Audience :: Information Technology',
    'Intended Audience :: System Administrators',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: BSD License',
    'Programming Language :: Python',
    'Operating System :: OS Independent',
    'Topic :: Internet',
    'Topic :: System :: Archiving :: Backup',
    'Topic :: System :: Distributed Computing',
]

setup(
    name='scatterbytes',
    version=VERSION,
    description='Library and CLI for accessing the ScatterBytes Network',
    author='Randall Smith',
    author_email='randall@scatterbytes.net',
    url='https://www.scatterbytes.net',
    packages=find_packages(),
    license="BSD License",
    install_requires=install_requires,
    tests_require=['nose>=0.11'],
    scripts=['scripts/sbnet'],
    classifiers = classifiers,
    cmdclass={
        'sbzip' : BuildZipPackage
    }
)
