from __future__ import print_function
from lib.common.process import TRACKED_PROCESSES
import logging
import socket
import subprocess
import json

logger = logging.getLogger(__name__)

class MonitorDtrace(object):
    def __init__(self,config):
        self.dtrace_command = 'syscall::open:entry { printf("{\'pid\':%d,\'file_path\':\'%s\',\'flag\':%d}\\n",pid,copyinstr(arg0),arg1); }'
        #store configurations
        self.config = config
        self._log()

    def _execute(self,cmd):
        popen = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
        for stdout_line in iter(popen.stdout.readline,""):
            yield stdout_line
        popen.stdout.close()
        return_code = popen.wait()
        if return_code:
            raise subprocess.CalledProcessError(return_code, cmd)
    
    def _log(self):
        buffer = []
        iteration_control = True
        socket_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_host.connect((self.config.ip, self.config.port))
        socket_host.send("JSON\n")
        socket_host.send("DTRACE\n")
        for log in self._execute(["sudo","dtrace","-qn",self.dtrace_command]):
            if TRACKED_PROCESSES:
                if iteration_control:
                    for buf in buffer:
                        json_buf = json.loads(buf)
                        if json_buf['pid'] in TRACKED_PROCESSES:
                            socket_host.send(buf.encode())
                    iteration_control = False
                string = log.encode().replace("'",'"')
                try:
                    json_string = json.loads(string)
                    if json_string['pid'] in TRACKED_PROCESSES:
                        socket_host.send(string.encode())
                except Exception as error:
                    logger.warning("JSON dump error: %s",error)
            else:
                string = log.encode().replace("'",'"')
                buffer.append(string)