"""Command Line Interface functionality

"""

import os
import sys
import socket
import getpass
import logging
import logging.handlers
import datetime
import textwrap
try:
    import daemon
    # called pidlockfile in standard debian distro
    try:
        import daemon.pidfile
    except ImportError:
        import daemon.pidlockfile
        daemon.pidfile = daemon.pidlockfile
except ImportError:
    daemon = None
from argparse import ArgumentParser
from . import errors
from . import validation


PID_PATH_DF = '/var/run/scatterbytes/scatterbytes-server.pid'

logger = logging.getLogger(__name__)

# Several imports are performed as needed to prevent loading uneeded modules.

logging.getLogger().setLevel(logging.DEBUG)


class PrettyProxy(object):
    """wrapper with nicer output"""

    def __init__(self, proxy):
        self._proxy = proxy

    def __getattr__(self, name):
        "print nice output for a recognized error"
        #if name.startswith('get_account'):
        #    import pdb; pdb.set_trace()
        attr = None
        if hasattr(self._proxy, name):
            attr = getattr(self._proxy, name, None)
        if attr and callable(attr):
            # wrap call to check output
            def new(*args, **kwargs):
                try:
                    return attr(*args, **kwargs)
                except errors.SBError as e:
                    out = '%s: %s' % (
                        e.__class__.__name__, str(e)
                    )
                    print out
                    sys.exit(1)
            return new
        elif attr:
            return attr
        raise AttributeError(name)


def create_client_node(*args, **kwargs):
    # wrapper to prevent multiple re-imports
    from .client.jsonrpc import create_client_node
    client_node = create_client_node(*args, **kwargs)
    return PrettyProxy(client_node)


def create_storage_node(*args, **kwargs):
    # wrapper to prevent multiple re-imports
    from .storage.jsonrpc import create_storage_node
    storage_node = create_storage_node(*args, **kwargs)
    return PrettyProxy(storage_node)


def start_server(args):

    from .storage.jsonrpc import start_server as start_storage_server

    daemonize = not args.nodaemon

    start_storage_server(daemonize=daemonize)


def get_daemon_pid(storage_node_config_path):
    if os.path.exists(PID_PATH_DF):
        return PID_PATH_DF
    # need to read the config
    from .storage.node import StorageNodeConfig
    config = StorageNodeConfig(storage_node_config_path)
    pid_path = os.path.join(config.data_directory, 'sbnet.pid')
    if os.path.exists(pid_path):
        return pid_path


def check_yesno(response, default='yes'):
    if not isinstance(response, basestring):
        return
    response = response.strip().lower()
    if response in ('yes', 'y'):
        return 'yes'
    if response in ('no', 'n'):
        return 'no'
    if not response:
        return default
    return None


def input_yesno(msg, default='yes'):
    # loop until get a proper response
    msg = msg + ' (y/n, default %s): ' % default[0]
    msg = textwrap.fill(msg) + ' '
    response = None
    while response is None:
        response = check_yesno(raw_input(msg), default)
    return response


def prompt_register(config):

    def register():
        client_node = create_client_node(config=config, verbosity=3)
        response = client_node.register(node_type, email, password)
        if response['errors']:
            print
            print 'The following errors are present:'
            print
            for (k, v) in response['errors'].items():
                print '%s: %s' % (k, v)
            print
            if input_yesno('Do you want to try agian?', 'no') == 'yes':
                prompt_register(config)
            return
        # no errors - proceed
        config.set('node_id', response['node_info']['node_id'])
        config.set('recert_code', response['node_info']['recert_code'])
        config.save()
        print
        msg = 'Account creation successful. Press [Enter] to continue: '
        response = raw_input(msg)
        return True

    # what type of config is this?
    if 'client' in config.__class__.__name__.lower():
        node_type = 'client'
    else:
        node_type = 'storage'

    msg = ('Your Node ID is not set. If you do not already have a '
           'Node ID, you can register now. Do you want to register '
           'now?')
    response = input_yesno(msg, 'yes')
    if response == 'no':
        return

    if node_type == 'storage':
        msg = 'Storage Nodes have the option of anonymous registration. '
        msg += 'This is the quickest way to get started, but it will not '
        msg += 'create an account for access through the website. '
        msg += 'Do you want to use anonymous registration?'
        print
        response = input_yesno(msg, 'yes')
        if response == 'yes':
            email = None
            password = None
            return register()

    print
    print 'The following information is needed to register:'
    print
    email_valid = False
    while email_valid is False:
        email = raw_input('Email Address: ')
        try:
            email = validation.Email(not_empty=True).to_python(email)
            email_valid = True
        except validation.Invalid as e:
            print e
            print
    print
    pass_ok = False
    while not pass_ok:
        password = getpass.getpass('Password: ')
        try:
            password = validation.SecurePassword.to_python(password)
        except validation.Invalid as e:
            print e
            print
            continue
        password_confirm = getpass.getpass('Confirm Password: ')
        if password != password_confirm:
            print 'passwords did not match'
        else:
            pass_ok = True
        register()
    return True


def set_encryption_passphrase(config=None, save=True):
    from .client.node import ClientNodeConfig
    from . import crypt
    if config is None:
        config = ClientNodeConfig.get_config()
    msg = ('Enter a passphrase for your key. If you leave it blank '
           'a random 256 bit passphrase will be created for you.')
    print textwrap.fill(msg)
    password_set = False
    while not password_set:
        pass1 = getpass.getpass()
        if not pass1:
            config.encrypt_passphrase = \
                crypt.stretch_passphrase(
                    os.urandom(32), output_format='base64'
                )
            print 'Generated a passphrase for you.'
            password_set = True
        else:
            pass2 = ''
            pass2 = getpass.getpass('Confirm Passphrase: ')
            if pass1 == pass2:
                # hash it
                hash = crypt.stretch_passphrase(
                    pass2, salt=config.get('node_id'), output_format='base64'
                )
                config.encrypt_passphrase = hash
                password_set = True
                msg = ('A hash of your password was stored in your '
                       'configuration file and will be '
                       'used to generate encryption keys for your files. '
                       'You should keep this hash safe because it can be used '
                       'to decrypt your files.')
                print
                print textwrap.fill(msg)
            else:
                print
                print 'Password Mismatch!'
                print
    if save:
        config.save()


def setup(config_class, node_factory):
    from .client.node import ClientNodeConfig
    config = config_class.get_config()
    print
    msg = 'Your configuration file is located at %s. ' % config.config_path
    msg += 'You can edit the configuration file with a text editor.'
    print textwrap.fill(msg)
    print
    if not config.get('node_id'):
        if not prompt_register(config):
            raw_node_id = raw_input('Enter the Node ID assigned to you: ')
            config.set('node_id', raw_node_id.strip())
    if not config.get('recert_code'):
        raw_recert_code = raw_input('Enter the Recert Code assigned to you: ')
        config.set('recert_code', raw_recert_code.strip())
    if config_class is ClientNodeConfig and config.encrypt_passphrase:
        set_encryption_passphrase(config, save=False)
    config.save()
    # See if we have a cert.
    if not os.path.exists(config.cert_path):
        print 'Fetching your certificate.'
        node = node_factory(config=config)
        node.request_new_certificate()
    if not config.encrypt_passphrase:
        set_encryption_passphrase(config)


def setup_storage_node(args):
    from .storage.node import StorageNodeConfig
    if args.make_config:
        config = StorageNodeConfig.get_config()
        print 'created config at %s' % config.config_path
        return


def setup_client_node(args):
    from .client.node import ClientNodeConfig
    if args.make_config:
        ClientNodeConfig.get_config()
        return
    elif args.set_passphrase:
        set_encryption_passphrase()
        return
    setup(ClientNodeConfig, create_client_node)


def proxy_cmd(f, mode='client'):
    def new_cmd(args):
        try:
            verbosity = args.verbosity
            if mode == 'storage':
                proxy = create_storage_node(verbosity=verbosity)
            else:
                proxy = create_client_node(verbosity=verbosity)
                proxy.check_certificate()
            return f(proxy, args)
        except socket.error as e:
            logger.error(
                'Unable to Connect - There may be a problem with your network '
                'connection or the host you are connecting to. '
                'Error was: %s' % str(e)
            )
        except errors.SBError as e:
            logger.error(e)
            sys.exit(1)
    return new_cmd


def show_account(proxy, args):
    response = proxy.show_account()
    print response
show_account = proxy_cmd(show_account, mode='storage')


@proxy_cmd
def list_volumes(client_node, args):
    response = client_node.list_volumes()
    print '*' * 10, 'Volume Information', '*' * 10
    print
    print ' ', 'Name'.ljust(20), 'Mirrors'.ljust(10), 'Bytes Stored'
    print
    for (name, v) in response['volumes'].items():
        s = '  '
        if name == 'default':
            s = '* '
        sys.stdout.write(s)
        sys.stdout.write(name.ljust(21))
        sys.stdout.write(str(v['mirror_count']).ljust(11)),
        sys.stdout.write(str(v['bytes_stored'])),
        print


@proxy_cmd
def create_volume(client_node, args):
    response = client_node.create_volume(args.volume_name, args.mirror_count)
    if 'message' in response:
        print response['message']


@proxy_cmd
def delete_volume(client_node, args):
    response = client_node.delete_volume(args.volume_name)
    if 'message' in response:
        print response['message']


@proxy_cmd
def update_volume(client_node, args):
    response = client_node.update_volume(
        args.volume_name, args.set_default, args.rename
    )
    if 'message' in response:
        print response['message']


@proxy_cmd
def upload_file(client_node, args):
    file_path = args.file_path
    volume_name = args.volume_name
    config = client_node.config
    encrypt = config.get('encrypt', section='data_prep')
    compress = config.get('compress', section='data_prep')
    file_chunks_path = client_node.prepare_file(
        file_path, encrypt=encrypt, compress=compress
    )
    client_node.upload_file_chunks(
        file_chunks_path, volume_name, file_name=args.file_name
    )


@proxy_cmd
def delete_file(client_node, args):
    file_name = args.file_name
    volume_name = args.volume_name
    response = client_node.delete_file(
        file_name, volume_name
    )
    if 'message' in response:
        print response['message']


@proxy_cmd
def download_file(client_node, args):
    file_name = args.file_name
    volume_name = args.volume_name
    output_path = args.output_path
    client_node.download_file(
        file_name, output_path, volume_name=volume_name
    )


def _format_column_data(column_data):
    if not column_data:
        return
    row_length = len(column_data[0])
    col_widths = [0, ] * row_length

    def make_print_value(value):
        if isinstance(value, datetime.datetime):
            print_value = value.strftime('%Y-%m-%d %H:%M')
        elif isinstance(value, datetime.date):
            print_value = value.strftime('%Y-%m-%d')
        else:
            try:
                print_value = str(value)
            except:
                return value
        return print_value
    # first, determine column widths and format data
    for row in column_data:
        for (i, value) in enumerate(row):
            print_value = make_print_value(value)
            if len(print_value) > col_widths[i]:
                col_widths[i] = len(print_value)
    # add padding
    new_data = []
    for row in column_data:
        new_row = ['', ] * row_length
        for (i, value) in enumerate(row):
            padding_size = col_widths[i]
            print_value = make_print_value(value)
            # make integers align right
            if isinstance(value, int):
                padded_value = print_value.rjust(padding_size).ljust(1)
            padded_value = print_value.ljust(padding_size + 1)
            new_row[i] = padded_value
        new_data.append(new_row)
    return new_data


def print_file_results(file_results, long_format, with_metadata):
    column_data = []
    column_metadata = []
    for rset in file_results:
        row = []
        if len(rset) == 1:
            row.append(rset[0])
        else:
            # size, init time, flags, file name
            row = [rset[i] for i in (1, 3, 2, 0)]
        if with_metadata:
            column_metadata.append(
                [('    ', k + ': ', v) for (k, v) in rset[4].items()]
            )
        column_data.append(row)
    if not column_data:
        print 'no files'
        return
    for (i, row) in enumerate(_format_column_data(column_data)):
        print ''.join(row)
        if with_metadata and column_metadata[i]:
            for m in _format_column_data(column_metadata[i]):
                print ''.join(m)


@proxy_cmd
def list_files(client_node, args):
    volume_name = args.volume_name
    long_format = args.long_format
    with_metadata = args.with_metadata
    detail_level = 0
    if long_format:
        detail_level = 1
    if with_metadata:
        detail_level = 2
    results = client_node.list_files(volume_name, detail_level)
    print_file_results(results, long_format, with_metadata)


def match_type(v):
    """guess at type and coerce"""
    from . import util
    if v is None or v.strip() == '':
        return None
    matched_v = None
    # try int
    if v.isdigit():
        try:
            matched_v = int(v)
        except:
            pass
    # try float:
    if not matched_v:
        try:
            matched_v = float(v)
        except:
            pass
    # try dt
    if not matched_v:
        matched_v = util.datetime_from_string(v)
    return matched_v or v


@proxy_cmd
def find_files(client_node, args):
    volume_name = args.volume_name
    long_format = args.long_format
    with_metadata = args.with_metadata
    detail_level = 0
    if long_format:
        detail_level = 1
    if with_metadata:
        detail_level = 2
    OPS = ['~', '=', '>', '>=', '<', '<=', 'IS']
    expr = ['AND']
    for m in args.search_criteria:
        found_op = None
        for o in OPS:
            if o in m:
                found_op = o
                break
        if found_op is None:
            emsg = 'expected an operator for comparison:  %s' % m
            raise errors.SBValueError(emsg)
        (k, v) = m.split(found_op)
        expr.append((k, found_op, match_type(v)))
    results = client_node.find_files(volume_name, expr, detail_level)
    print_file_results(results, long_format, with_metadata)


@proxy_cmd
def update_file(client_node, args):
    metadata = {}
    file_name = args.file_name
    volume_name = args.volume_name

    for m in args.metadata:
        (k, v) = m.split('=')
        v = match_type(v)
        metadata[k] = v
    client_node.update_file(
        volume_name, file_name, metadata
    )


def create_parsers():

    # see if config files exist
    from .storage.node import StorageNodeConfig
    storage_node_config_path = StorageNodeConfig.find_config_path()
    from . import __version__ as version

    parser = ArgumentParser(prog='sbnet')
    parser.add_argument(
        '--version', action='version',
        version='%(prog)s ' + version
    )
    parser.add_argument(
        '--verbosity', help='level of output verbosity (0-3)', type=int,
        default=None
    )
    subparsers = parser.add_subparsers(help='sub-command help')
    # storage node server
    server_parser = subparsers.add_parser(
        'server', help="storage node server command"
    )
    server_parsers = server_parser.add_subparsers(help='server commands')
    # storage node setup
    storage_setup_parser = server_parsers.add_parser(
        'setup', help='configure storage node'
    )
    storage_setup_parser.add_argument(
        '--make-config', '-c', action='store_true',
        help='create a skeleton config only'
    )
    storage_setup_parser.set_defaults(func=setup_storage_node)
    # start storage node
    if os.path.exists(storage_node_config_path):
        start_server_parser = server_parsers.add_parser(
            'start', help='startup storage node server'
        )
        if daemon:
            start_server_parser.add_argument(
                '--nodaemon', '-d', action='store_true',
                help='do not daemonize process'
            )
        start_server_parser.set_defaults(func=start_server)
    if daemon and os.path.exists(storage_node_config_path):
        import signal
        daemon_pid_file_path = get_daemon_pid(storage_node_config_path)
        if daemon_pid_file_path:
            shutdown_parser = server_parsers.add_parser(
                'stop', help='shutdown storage node server'
            )

            def shutdown_storage_node(parser_args):
                print 'sending process TERM signal'
                os.kill(
                    int(open(daemon_pid_file_path).read()),
                    signal.SIGTERM
                )
            shutdown_parser.set_defaults(func=shutdown_storage_node)
    # server account
    account_parser = server_parsers.add_parser(
        'account', help='show account information'
    )
    account_parser.set_defaults(func=show_account)
    client_setup_parser = subparsers.add_parser(
        'setup', help='configure client node'
    )
    client_setup_parser.add_argument(
        '--make-config', '-c', action='store_true',
        help='create a skeleton config only'
    )
    client_setup_parser.add_argument(
        '--set-passphrase', '-p', action='store_true',
        help='set the encryption passphrase'
    )
    client_setup_parser.set_defaults(func=setup_client_node)
    # list volumes
    list_volume_parser = subparsers.add_parser(
        'list-volumes', help='list volumes'
    )
    list_volume_parser.set_defaults(func=list_volumes)
    # create volume
    create_volume_parser = subparsers.add_parser(
        'create-volume', help='create a new volume'
    )
    create_volume_parser.add_argument(
        'volume_name', type=str, help='volume name'
    )
    create_volume_parser.add_argument(
        '--mirror-count', type=int, default=3, help='number of mirrors',
    )
    create_volume_parser.set_defaults(func=create_volume)
    # delete volume
    delete_volume_parser = subparsers.add_parser(
        'delete-volume', help='delete a volume'
    )
    delete_volume_parser.add_argument(
        'volume_name', type=str, help='volume name'
    )
    delete_volume_parser.set_defaults(func=delete_volume)
    # update volume
    update_volume_parser = subparsers.add_parser(
        'update-volume', help='update a volume'
    )
    update_volume_parser.add_argument(
        'volume_name', type=str, help='volume name'
    )
    update_volume_parser.add_argument(
        '--set-default', '-d', default=False, type=bool,
        help='set the default volume'
    )
    update_volume_parser.add_argument(
        '--rename', '-n', default='', type=str, help='rename the volume'
    )
    update_volume_parser.set_defaults(func=update_volume)
    # upload file
    upload_parser = subparsers.add_parser(
        'upload', help='upload a file'
    )
    upload_parser.add_argument(
        'file_path', type=str, help='path to the file'
    )
    upload_parser.add_argument(
        '--volume-name', '-v', type=str, help='volume to put the file on'
    )
    upload_parser.add_argument(
        '--file-name', '-n', type=str, help='name to refernece this file with'
    )
    upload_parser.set_defaults(func=upload_file)
    # delete file
    delete_parser = subparsers.add_parser(
        'delete', help='delete a file'
    )
    delete_parser.add_argument(
        'file_name', type=str, help='name of the file to delete'
    )
    delete_parser.add_argument(
        '--volume-name', '-v', type=str,
        help='volume on which the file resides'
    )
    delete_parser.set_defaults(func=delete_file)
    # download file
    download_parser = subparsers.add_parser(
        'download', help='download a file'
    )
    download_parser.add_argument(
        'file_name', type=str, help='name of the file to download'
    )
    download_parser.add_argument(
        'output_path', type=str,
    )
    download_parser.add_argument(
        '--volume-name', '-v', type=str, default=None,
        help='volume on which the file resides'
    )
    download_parser.set_defaults(func=download_file)
    # list files
    list_parser = subparsers.add_parser(
        'list', help='list all files'
    )
    list_parser.add_argument(
        '--volume-name', '-v', type=str, default=None,
        help='volume on which to list files'
    )
    list_parser.add_argument(
        '--long-format', '-l', action='store_true',
        help='show init date, size and flags'
    )
    list_parser.add_argument(
        '--with-metadata', '-m', action='store_true',
        help='include metadata'
    )
    list_parser.set_defaults(func=list_files)
    # search files
    find_parser = subparsers.add_parser(
        'find', help='find files'
    )
    find_parser.add_argument(
        '--volume-name', '-v', type=str, default=None,
        help='volume on which to search files'
    )
    find_parser.add_argument(
        '--long-format', '-l', action='store_true',
        help='show init date, size and flags'
    )
    find_parser.add_argument(
        '--with-metadata', '-m', action='store_true',
        help='include metadata'
    )
    find_parser.add_argument(
        'search_criteria', type=str, help='criteria for search',
        nargs='*'
    )
    find_parser.set_defaults(func=find_files)
    # update file
    file_update_parser = subparsers.add_parser(
        'update', help='update file metadata'
    )
    file_update_parser.add_argument(
        'file_name', type=str, help='filename to update'
    )
    file_update_parser.add_argument(
        '--volume-name', '-v', type=str, default=None,
        help='volume on which file resides'
    )
    file_update_parser.add_argument(
        '--metadata', '-m',
        help='update metadata', nargs='*'
    )
    file_update_parser.set_defaults(func=update_file)

    return parser


def run():
    parser = create_parsers()
    args = parser.parse_args()
    args.func(args)
