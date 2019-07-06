import subprocess
import time
import os
import sys
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
		#execute the sample
		self._execute()

	def _prepare_env(self):
		#In case, environment needs to be taken care of, put all of it in here
		#Such as setting the clock, turning of or on services. Depends on configurations
		
		#Give executable permission to target
		os.system("sudo chmod +x " + self.target_sample)

	def _execute(self):
		#The execution process goes here.
		target_process = subprocess.Popen(['sh', self.target_sample], shell=False, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
		#fetch target PID
		self.exec_time = time.time()
		self.target_pid = target_process.pid


