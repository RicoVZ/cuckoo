# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import sys
import os
import urllib
import urllib2
import socket
import logging
import time
from lib.common.results import NetlogHandler 
from lib.common.config import Config
from lib.core.packages import _initiate_recognition

#TODOs:
#Determine why status is not getting updated, even while requesting to agent properly.
#Set up a method to enfore timeout if configured.
#Add support for URL category.
log = logging.getLogger("analyzer")


class darwin_analyser(object):
    log = logging.getLogger()
    #Cuckoo mac OS analyser --> Supporing Sierra/High Sierra/Mojave
    def __init__(self, configuration=None):
        #storing user configurations
        self.config = configuration
        self.package_path = None
        self.XNUMON_HOST = "127.0.0.1"
        self.XNUMON_PORT = 4343
    def run(self):
        #Initiate analysis
        _setup_logging()
        log.debug("Initializing analysis")
        #Send configurations to xnumon
        self._upload_to_xnumon()
        log.debug("Configurations delivered to Xnumon daemon")
        #Storing the package path
        self.package_path = os.path.join(os.getcwd(), self.config.file_name)
        #Determining target type File/URL
        self._detect_target()
        #Passing file to file handler
        self._handle_package()
        log.debug("Triggering Sample")
        self._monitor_timeout()

    def _upload_to_xnumon(self):
        socket_xnumon = socket.socket()
        socket_xnumon.connect((self.XNUMON_HOST, self.XNUMON_PORT))
        log.debug("Connected to Xnumon agent")
        file = open('analysis.conf','rb')
        data = file.read(1024)
        log.debug("Transferring configurations to Xnumon agent")
        while (data):
            socket_xnumon.send(data)
            data = file.read(1024)
        file.close()
        socket_xnumon.shutdown(socket.SHUT_WR)
        socket_xnumon.close

    def _detect_target(self):
        if self.config.category == "file":
            self.target = self.package_path
        else:
            self.target = self.config.target

    def _handle_package(self):
        if self.config.category == "file":
            suggestion = None
            if (self.config.package):
                suggestion = self.config.package
            if suggestion:
                kwargs = {
                    "suggestion":suggestion,
                    "package_path":self.package_path
                }
            else:
                kwargs = {
                    "package_path":self.package_path
                }            
            self.target_pid, self.exec_time = _initiate_recognition(self.config.file_type, self.config.file_name, **kwargs)
    def _check_pid(self, pid):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True
    def _monitor_timeout(self):
        data = {
            "status": "complete",
            "description": "Timeout is encountered, aborting analysis",
        }
        #enforce_timeout:true
        if (self.config.timeout):
            log.debug("Timeout detected")
            end_point = self.config.tiemout + self.exec_time
            #check every second
            iteration_control = True 
            while iteration_control:
                if(time.time() >= end_point):
                    urllib2.urlopen("http://127.0.0.1:8000/status",urllib.urlencode(data)).read()
                    iteration_control=False
                time.sleep(2)
        #enforce_timeout:false
        else:
            #wait by default for 5 seconds
            time.sleep(5)
            #then check if process is still active
            iteration_control = True 
            while iteration_control:
                if self._check_pid(self.target_pid):
                    urllib2.urlopen("http://127.0.0.1:8000/status",urllib.urlencode(data)).read()
                    iteration_control=False
                time.sleep(1)
def _setup_logging():
    #Initiate Loggings
    logger = logging.getLogger()
    formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    netlog = NetlogHandler()
    netlog.setFormatter(formatter)
    logger.addHandler(netlog)
    logger.setLevel(logging.DEBUG)       

if __name__ == "__main__":
    config = Config(cfg="analysis.conf")
    analyser_instance = darwin_analyser(config)
    analyser_instance.run()
        

