# rundeck-winsmb-plugin
A rundeck plugin use SMB to connect with Windows

# prerequisite
>You should intsall impacket and winexe:
>  pip install impacket
>  yum install winexe

# conf
>when add windows node in resources.xml,it will be like this:
> <node name="xxx" description="" tags="windows" hostname="xxx" osArch="" osFamily="windows" osName="windows" osVersion="" username="administrator" file-copier="WinSMBcp" node-executor="WinSMBexe" win-password-storage-path="xxx"/>

>note: the file-copier="WinSMBcp" node-executor="WinSMBexe" is unchangeable
