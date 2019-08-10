from __future__ import print_function
from lib.common.process import TRACKED_PROCESSES
import subprocess
import socket
import json
import os
import signal
import sys

class InitiateMonitor(object):
    def __init__(self, config):
        self.PID_PATH = '/private/var/run/xnumon.pid'
        self.RELEVANT_EVENTCODES = (2,3,4)
        self.XNUMON_PATH = '/usr/local/sbin'
        #change working directory
        os.chdir(self.XNUMON_PATH)
        #store configurations
        self.config = config

    def _run(self):
        # kill existing xnumon instance
        self._kill_existing()
        # initiate logging
        self._log()

    def _kill_existing(self):
        if os.path.isfile(self.PID_PATH):
            os.remove(self.PID_PATH)

    def _execute(self):
        popen = subrpocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
        for stdout_line in iter(popen.stdout.readline,""):
            yield stdout_line
        popen.stdout.close()
        return_code = popen.wait()
        if return_code:
            raise subprocess.CalledProcessError(return_code, cmd)

    def _check_relevance(self,log):
        json_string = json.loads(log)
        if json_string["eventcodes"] in self.RELEVANT_EVENTCODES:
            if json_string["subject"]["pid"] in TRACKED_PROCESSES or json_string["subject"]["image"]["exec_pid"] in TRACKED_PROCESSES:
                return True
            elif json_string["subject"]["ancestors"]:
                for ancestor in json_string["subject"]["ancestors"]:
                    if ancestor["exec_pid"] in TRACKED_PROCESSES:
                        TRACKED_PROCESSES.append(json_string["subject"]["pid"])
                        return True
        else:
            return False


    def _log(self):
        buffer_events = []
        socket_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_host.connect((self.config.ip, self.config.port))
        socket_host.connect("JSON\n")
        for log in self._execute(["sudo", "./xnumon", "-d"]):
            if TRACKED_PROCESSES:
                iteration_control = True
                #if there are buffer logged before sample is triggered
                if buffer_events:
                    while iteration_control:
                        for item in buffer_events:
                            if self._check_relevance(item):
                                socket_host.send(item.encode())
                        iteration_control = False
                #check if log is relevant to target anyways
                if self._check_relevance(log):
                    socket_host.send(log.encode())
            else:
                buffer_events += log


