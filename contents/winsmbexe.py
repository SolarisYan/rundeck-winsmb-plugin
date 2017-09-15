#!/usr/bin/python

import os
import logging
import subprocess

from nb_popen import NonBlockingPopen

# try:
#     import impacket.smbconnection
#     from impacket.smbconnection import SessionError as smbSessionError
#     from impacket.smb3 import SessionError as smb3SessionError
#     HAS_IMPACKET = True
# except ImportError:
#     HAS_IMPACKET = False

log = logging.getLogger(__name__)

# def get_conn(host=None, username=None, password=None):
#     '''
#     Get an SMB connection
#     '''
#     if not HAS_IMPACKET:
#         return False

#     conn = impacket.smbconnection.SMBConnection(
#         remoteName='*SMBSERVER',
#         remoteHost=host, )
#     conn.login(user=username, password=password)
#     return conn


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
            log.info('Executing command(PID %s): \'%s\'', proc.pid,
                     exe_command)
        else:
            log.info('Executing command(PID %s): \'%s\'', proc.pid,
                     logging_command)

        proc.poll_and_read_until_finish()
        # proc.communicate()
        stdout, stderr = proc.communicate()
        # proc.communicate(input='\n')
        # return proc.returncode
        return (stdout, stderr, proc.returncode)
    except Exception as err:
        with open('/tmp/winsmbexe.log', 'a+') as fp_:
            fp_.write('Failed to execute command \'{0}\': {1}\n'.format(
                logging_command, err))
        # log.info(
        #     'Failed to execute command \'{0}\': {1}\n'.format(
        #         logging_command, err),
        #     exc_info=True)
        # Signal an error
        return (None, None, 1)


def execute_cmd(exe_cmd, host, user, passwd):
    creds = "-U '{0}%{1}' //{2}".format(user, passwd, host)
    logging_creds = "-U '{0}%XXX-REDACTED-XXX' //{1}".format(user, host)
    # cmd = 'winexe {0} "{1}"'.format(creds, exe_cmd)
    # logging_cmd = 'winexe {0} "{1}"'.format(logging_creds, exe_cmd)
    cmd = 'winexe {0} "powershell -inputformat none -command {1}"'.format(
        creds, exe_cmd)
    logging_cmd = 'winexe {0} "powershell -inputformat none -command {1}"'.format(
        logging_creds, exe_cmd)
    return win_cmd(cmd, logging_command=logging_cmd)


def get_executionpolicy(host, user, passwd):
    cmd = "get-executionpolicy"
    ret = execute_cmd(cmd, host, user, passwd)
    policy = ret[0]
    if policy:
        return policy.replace('\n', '').replace('\r', '').lower()
    return ret[1]


def set_executionpolicy(host, user, passwd):
    cmd = "set-executionpolicy RemoteSigned -Force"
    execute_cmd(cmd, host, user, passwd)
    policy = get_executionpolicy(host, user, passwd)
    return policy


def execute_ps_cmd(command, host, user, passwd):
    """
    real execute the rundeck cmd or powershell script
    """
    if '.ps1' in command:
        policy = get_executionpolicy(host, user, passwd)
        if policy == 'restricted':
            policy = set_executionpolicy(host, user, passwd)
        if policy == 'restricted':
            desc = "can't set the powershell executionpolicy!"
            with open('/tmp/winsmbexe.log', 'a+') as fp_:
                fp_.write('desc:{0}\n'.format(desc))
            raise Exception(desc)

    # Wrapper for avoid unix style file copying then scripts run
    # - not accept chmod call
    # - replace rm -f into rm -force
    # - auto copying renames file from .sh into .ps1 in tmp directory

    if 'chmod +x' in command:
        exit(0)
    if '-f' in command:
        command = command.replace('-f', '-Force')
    if '.sh' in command:
        command = command.replace('.sh', '.ps1')
    if command.startswith('/tmp/'):
        command = 'c:{0}'.format(command)

    # command = "powershell {0}".format(command)
    # command = "powershell -inputformat none -command {0}".format(command)

    with open('/tmp/winsmbexe.log', 'a+') as fp_:
        fp_.write('command:{0}\n'.format(command))

    # ret = execute_cmd(command, hostname, username, password)
    ret_stdout, ret_stderr, ret_code = execute_cmd(command, host, user, passwd)

    with open('/tmp/winsmbexe.log', 'a+') as fp_:
        fp_.write('stdout:{0}, stderr:{1},retcode:{2}\n'.format(
            ret_stdout, ret_stderr, ret_code))

    exit(ret_code)


rd_command = os.getenv('RD_EXEC_COMMAND')
rd_hostname = os.getenv('RD_NODE_HOSTNAME')
rd_username = os.getenv('RD_NODE_USERNAME')
rd_password = os.getenv('RD_CONFIG_PASS')

execute_ps_cmd(rd_command, rd_hostname, rd_username, rd_password)
