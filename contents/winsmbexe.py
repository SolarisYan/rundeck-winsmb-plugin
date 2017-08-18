#!/usr/bin/python

import os
import logging
import subprocess

from nb_popen import NonBlockingPopen

try:
    import impacket.smbconnection
    from impacket.smbconnection import SessionError as smbSessionError
    from impacket.smb3 import SessionError as smb3SessionError
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

log = logging.getLogger(__name__)


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


def win_cmd(exe_command, **kwargs):
    '''
    Wrapper for commands to be run against Windows boxes
    '''
    logging_command = kwargs.get('logging_command', None)

    try:
        proc = NonBlockingPopen(
            exe_command,
            shell=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stream_stds=kwargs.get('display_ssh_output', True),
            logging_command=logging_command, )

        if logging_command is None:
            log.info('Executing command(PID %s): \'%s\'', proc.pid, exe_command)
        else:
            log.info('Executing command(PID %s): \'%s\'', proc.pid,
                     logging_command)

        proc.poll_and_read_until_finish()
        proc.communicate()
        return proc.returncode
    except Exception as err:
        log.info(
            'Failed to execute command \'{0}\': {1}\n'.format(logging_command,
                                                              err),
            exc_info=True)
    # Signal an error
    return 1


def execute_cmd(exe_cmd, host, user, passwd):
    creds = "-U '{0}%{1}' //{2}".format(user, passwd, host)
    logging_creds = "-U '{0}%XXX-REDACTED-XXX' //{1}".format(user, host)
    cmd = 'winexe {0} "{1}"'.format(creds, exe_cmd)
    logging_cmd = 'winexe {0} "{1}"'.format(logging_creds, exe_cmd)
    return win_cmd(cmd, logging_command=logging_cmd)


hostname = os.getenv('RD_NODE_HOSTNAME')
username = os.getenv('RD_NODE_USERNAME')
password = os.getenv('RD_CONFIG_PASS')
command = os.getenv('RD_EXEC_COMMAND')

if '.ps1' in command:
    command = "powershell {0}".format(command)

with open('/tmp/winsmbexe.log', 'a+') as fp_:
    fp_.write('command:{0}\n'.format(command))

ret = execute_cmd(command, hostname, username, password)
with open('/tmp/winsmbexe.log', 'a+') as fp_:
    fp_.write('ret:{0}\n'.format(ret))
exit(ret)
