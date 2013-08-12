#!/usr/bin/env python

import os
import shutil
import tarfile
import logging
import datetime
import subprocess

from argparse import ArgumentParser

logger = logging.getLogger(__name__)

TMP_DIR='/tmp/sbdeb'

SCRIPT_DIR = os.path.abspath(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '../../'))
PUBLISH_HOST=os.environ.get('SB_PUBLISH_HOST')
PUBLISH_PATH=os.environ.get('SB_PUBLISH_PATH')
REPO_PATH=PUBLISH_PATH


def get_version():
    version_path = os.path.join(ROOT_DIR, 'VERSION')
    version = open(version_path).read().strip()
    return version

def get_pysrc_path():
    version = get_version()
    pkg_name = 'scatterbytes-cli-%s.tar.gz' % version
    pysrc_path = os.path.join(ROOT_DIR, 'dist', pkg_name)
    return pysrc_path

def update_files(debian_path):
    # update files needing timestamps, etc
    copyright_path = os.path.join(debian_path, 'debian', 'copyright')
    copyright_lines = open(copyright_path).readlines()
    # replace the second line
    format = '%a, %d %b %Y %H:%M:%S +0000.'
    now = datetime.datetime.utcnow().strftime(format)
    copyright_lines[1] = now + '\n'
    open(copyright_path, 'wb').writelines(copyright_lines)
    os.chdir(debian_path)
    cmd = ['./update_debian_changelog.sh']
    ret = subprocess.check_call(cmd)
    os.chdir(ROOT_DIR)

def build_pysrc(check_exists=True):
    pysrc_path = get_pysrc_path()
    if check_exists and pysrc_path and os.path.exists(pysrc_path):
        logger.info('already packaged - not building')
        return
    os.chdir(ROOT_DIR)
    tfile = tarfile.open(pysrc_path, 'w:gz')
    tinfo = tfile.gettarinfo('scripts/sbnet')
    def reset(tarinfo):
        tinfo.uname = 'root'
        tinfo.gname = 'root'
        tinfo.uid = 0
        tinfo.gid = 0
        tinfo.mode = 0755
        tinfo.name = os.path.join(os.path.basename(pysrc_path)[:-7], 'sbnet')
        return tinfo
    tfile.add('scripts/sbnet', filter=reset)
    tfile.close()

def copy_pysrc():
    # copy it into our directory and name it properly
    version = get_version()
    pkg_name = 'scatterbytes-cli-%s.tar.gz' % version
    pkg_name_deb = 'scatterbytes-cli_%s.orig.tar.gz' % version
    src_path = os.path.join(ROOT_DIR, 'dist', pkg_name)
    assert os.path.exists(src_path)
    tgt_path = os.path.join(TMP_DIR, pkg_name_deb)
    shutil.copy(src_path, tgt_path)

def unpack_pysrc():
    # unpack it
    os.chdir(TMP_DIR)
    pkg_name = 'scatterbytes-cli-%s.tar.gz' % get_version()
    pkg_name_deb = 'scatterbytes-cli_%s.orig.tar.gz' % get_version()
    tar = tarfile.open(pkg_name_deb)
    tar.extractall()
    tar.close()
    os.chdir(ROOT_DIR)
    # return the name of the src directory
    return os.path.join(TMP_DIR, pkg_name[:-7])

def build_deb(src_dir, with_source=True):
    os.chdir(src_dir)
    cmd = ['debuild', '-k%s' % os.environ.get('DEBSIGN_KEYID')]
    if not with_source:
        cmd.append('-b')
    print cmd
    subprocess.check_call(cmd)

    # look for the changes file
    flist = os.listdir('../')
    changes_f = None
    for f in flist:
        if f.endswith('changes'):
            changes_f = f
            break
    assert changes_f, 'did not find changes file'
    os.chdir('%s/apt/debian' % REPO_PATH)
    changes_path = '/tmp/sbdeb/%s' % changes_f
    cmd = ['reprepro', 'include', 'unstable', changes_path]
    subprocess.check_call(cmd)
    os.chdir(ROOT_DIR)

def publish_deb(dest_host, dest_path):
    # sync it
    src_path = REPO_PATH
    tgt_path = '%s:' % dest_host + dest_path
    cmd = ['rsync', '-aLv', '--delete', src_path, tgt_path]
    subprocess.check_call(cmd)
    # remove the conf and db directories
    deb_tgt=os.path.join(dest_path, 'apt', 'debian')
    cmd = ['ssh', dest_host,
           'rm -rf %(tgt)s/db %(tgt)s/conf' % dict(tgt=deb_tgt)]
    subprocess.check_call(cmd)

def parse_args():
    parser = ArgumentParser(description='Build a Debian Package')
    subparser = parser.add_subparsers(
        title='subcommands', description='subcommands',
        dest='subparser_name'
    )
    p1 = subparser.add_parser('build')
    p1.add_argument('package_name')
    p2 = subparser.add_parser('repo')
    p2.add_argument('repo_action', help='build or publish')
    return parser.parse_args()

def main():
    pargs = parse_args()
    sp_name = pargs.subparser_name
    if sp_name == 'repo':
        repo_action = pargs.repo_action
        if repo_action == 'build':
            build_repo()
        elif repo_action == 'publish':
            publish_deb(PUBLISH_HOST, PUBLISH_PATH)
        return
    else:
        package_name = pargs.package_name
    os.chdir(ROOT_DIR)
    if os.path.exists(TMP_DIR):
        shutil.rmtree(TMP_DIR)
    os.mkdir(TMP_DIR)
    if package_name == 'server':
        update_files(
            os.path.join(ROOT_DIR, 'packaging', 'apt', 'debian_server')
        )
        # copy deb directory
        deb_src = os.path.join(
            ROOT_DIR, 'packaging', 'apt', 'debian_server', 'debian'
        )
        tgt_name = 'scatterbytes_server_%s' % get_version()
        os.mkdir(os.path.join(TMP_DIR, tgt_name))
        deb_tgt = os.path.join(TMP_DIR, tgt_name, 'debian')
        shutil.copytree(deb_src, deb_tgt)
        build_deb(os.path.join(TMP_DIR, tgt_name), with_source=False)
    elif package_name == 'repo':
        update_files(
            os.path.join(ROOT_DIR, 'packaging', 'apt', 'debian_repo_pkg')
        )
        # copy deb directory
        deb_src = os.path.join(
            ROOT_DIR, 'packaging', 'apt', 'debian_repo_pkg', 'debian'
        )
        tgt_name = 'scatterbytes_repository_%s' % get_version()
        os.mkdir(os.path.join(TMP_DIR, tgt_name))
        deb_tgt = os.path.join(TMP_DIR, tgt_name, 'debian')
        shutil.copytree(deb_src, deb_tgt)
        build_deb(os.path.join(TMP_DIR, tgt_name), with_source=False)
    elif package_name == 'base':
        update_files(
            os.path.join(ROOT_DIR, 'packaging', 'apt', 'debian_base')
        )
        build_pysrc()
        copy_pysrc()
        src_dir = unpack_pysrc()
        # copy deb directory
        deb_src = os.path.join(
            ROOT_DIR, 'packaging', 'apt', 'debian_base', 'debian'
        )
        deb_tgt = os.path.join(src_dir, 'debian')
        shutil.copytree(deb_src, deb_tgt)
        # move script into place
        tgt_dir = os.path.join(deb_tgt, 'fs', 'usr', 'bin')
        os.makedirs(tgt_dir)
        tgt_path = os.path.join(tgt_dir, 'sbnet')
        shutil.move(
            os.path.join(src_dir, 'sbnet'),
            tgt_path
        )
        build_deb(src_dir)
    os.chdir(ROOT_DIR)


if __name__ == '__main__':
    main()
