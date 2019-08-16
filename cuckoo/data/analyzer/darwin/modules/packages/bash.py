import subprocess
import time
import os
import sys
import logging

log = logging.getLogger(__name__)
#Use subprocess instead of OS, as it is easier to grasp the PID of the process spawned
#which can be returned and handled for execution span configurations.
#The job of this module is to take the INPUT file, create necessary environment, spawan the target process and return the
#execution time and PID(Process Identififer)
class Bash(object):
	def __init__(self, package_path=None, configuration=None):
		#All the initiation parameters goes here. Store the necessary configurations
		self.target_sample = package_path
		#Prepare the environment
		self._prepare_env()

	def _prepare_env(self):
		#In case, environment needs to be taken care of, put all of it in here
		#Such as setting the clock, turning of or on services. Depends on configurations
		
		#Give executable permission to target
		os.system("sudo chmod +x " + self.target_sample)

	def execute(self):
		#The execution process goes here.
		target_process = subprocess.Popen(['/bin/bash', self.target_sample],stderr=subprocess.PIPE, stdout=subprocess.PIPE)
		stdout , stderr = target_process.communicate()
		#if there's no error, set the target process.
		if stdout or stderr:
			log.debug("STDOUT:%s STDERR:%s", stdout, stderr)
		return target_process.pid


