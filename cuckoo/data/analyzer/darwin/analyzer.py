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
import threading
from modules.auxiliary.xnumon import InitiateMonitor
from lib.common.process import TRACKED_PROCESSES
from lib.common.results import NetlogHandler
from lib.common.config import Config
from lib.core.packages import _initiate_recognition

# TODOs:
# Determine why status is not getting updated, even while requesting to agent properly.
# Set up a method to enfore timeout if configured.
# Add support for URL category.
log = logging.getLogger("analyzer")


class darwin_analyser(object):
    log = logging.getLogger()
    # Cuckoo mac OS analyser --> Supporing Sierra/High Sierra/Mojave

    def __init__(self, configuration=None):
        # storing user configurations
        self.config = configuration
        self.package_path = None

    def run(self):
        # Initiate analysis
        _setup_logging()
        log.debug("Initializing analysis")
        #initializing xnumon
        xnumon_daemon = threading.Thread(target=self._initiate_xnumon)
        xnumon_daemon.daemon = True
        xnumon_daemon.start()
        log.debug("Started Xnumon Daemon")
        #Storing the package path
        self.package_path = os.path.join(os.getcwd(), self.config.file_name)
        # Determining target type File/URL
        self._detect_target()
        # Passing file to file handler
        self._handle_package()
        log.debug("Triggering Sample")
        self._monitor_timeout()

    def _initiate_xnumon(self):
        monitor = InitiateMonitor(self.config)
        monitor._run()

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
                    "suggestion": suggestion,
                    "package_path": self.package_path
                }
            else:
                kwargs = {
                    "package_path": self.package_path
                }
            self.target_pid, self.exec_error = _initiate_recognition(
                self.config.file_type, self.config.file_name, **kwargs)
            if(self.exec_error != None):
                data = {
                    "status": "exception",
                    "description": self.exec_error,
                }
                urllib2.urlopen("http://127.0.0.1:8000/status",urllib.urlencode(data)).read()
                log.debug('3')
            else:
                TRACKED_PROCESSES.append(self.target_pid)
                log.debug('Adding process to TRACKED_PROCESSES : %s',str(TRACKED_PROCESSES))


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
        timeout_counter = 0
        iteration_control = True
        while(iteration_control):
            if(timeout_counter >= self.config.timeout):
                iteration_control = False
                urllib2.urlopen("http://127.0.0.1:8000/status",urllib.urlencode(data)).read()
            time.sleep(1)
            timeout_counter += 1
        

def _setup_logging():
    # Initiate Loggings
    logger = logging.getLogger()
    formatter = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s")

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
