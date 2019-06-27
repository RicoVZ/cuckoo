# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import os
import urllib
import urllib2
from lib.common.config import Config
from lib.core.packages import _initiate_recognition

#TODOs:
#Determine why status is not getting updated, even while requesting to agent properly.
#Set up a method to enfore timeout if configured.

class darwin_analyser(object):
    #Cuckoo mac OS analyser --> Supporing Sierra/High Sierra/Mojave
    def __init__(self, configuration=None):
        #storing user configurations
        self.config = configuration
        self.package_path = None
    def run(self):
        #Initiate analysis
        #Storing the package path
        self.package_path = os.path.join(os.getcwd(), self.config.file_name)
        #Determining target type File/URL
        self._detect_target()
        #Passing file to file handler
        self._handle_package()

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
            sys.stdout.write(str(self.exec_time))
        

if __name__ == "__main__":
    config = Config(cfg="analysis.conf")
    analyser_instance = darwin_analyser(config)
    analyser_instance.run()
        

