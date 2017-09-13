#!/usr/bin/python

import os
import sys

try:
    import impacket.smbconnection
    from impacket.smbconnection import SessionError as smbSessionError
    from impacket.smb3 import SessionError as smb3SessionError
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False


def get_conn(host=None, username=None, password=None):
    '''
    Get an SMB connection
    '''
    if not HAS_IMPACKET:
        return False

    conn = impacket.smbconnection.SMBConnection(
        remoteName='*SMBSERVER',
        remoteHost=host, )
    conn.login(user=username, password=password)
    return conn


def mkdirs(path,
           share='C$',
           conn=None,
           host=None,
           username=None,
           password=None):
    '''
    Recursively create a directory structure on an SMB share
    Paths should be passed in with forward-slash delimiters, and should not
    start with a forward-slash.
    '''
    if conn is None:
        conn = get_conn(host, username, password)

    if conn is False:
        return False

    with open('/tmp/winsmbcp.log', 'a+') as fp_:
        fp_.write('path:{0}\n'.format(path))

    comps = path.split('/')
    pos = 1
    for comp in comps:
        cwd = '/'.join(comps[0:pos])
        with open('/tmp/winsmbcp.log', 'a+') as fp_:
            fp_.write('cwd:{0}\n'.format(cwd))
        try:
            conn.listPath(share, cwd)
        except (smbSessionError, smb3SessionError) as exc:
            conn.createDirectory(share, cwd)
        pos += 1


def put_file(src_file, dest_dir, hostname, username, password):

    src_comps = src_file.split('/')
    file_name = src_comps[-1]

    dest_dir = dest_dir.replace('\\', '/')
    dest_comps = dest_dir.split('/')
    share = dest_comps[0].replace(':', '$')
    suffix = dest_comps[-1][-3:]
    if dest_comps[-1] != file_name and suffix not in ['ps1', 'bat']:
        dest_comps.append(file_name)
    dest_file = '/'.join(dest_comps[1:])
    mid_path = '/'.join(dest_comps[1:-1])

    smb_conn = get_conn(hostname, username, password)
    mkdirs(mid_path, share, smb_conn)

    with open(src_file, 'rb') as inst_fh:
        smb_conn.putFile(share, '{0}'.format(dest_file), inst_fh.read)


rd_hostname = os.getenv('RD_NODE_HOSTNAME')
rd_username = os.getenv('RD_NODE_USERNAME')
rd_password = os.getenv('RD_CONFIG_PASS')

rd_src_file = sys.argv[1]
rd_dest_dir = sys.argv[2]

with open('/tmp/winsmbcp.log', 'a+') as fp_:
    fp_.write('src_file:{0}\n dest_dir:{1}\n'.format(rd_src_file, rd_dest_dir))

put_file(rd_src_file, rd_dest_dir, rd_hostname, rd_username, rd_password)
