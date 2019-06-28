import subprocess
import time
import os
#Use subprocess instead of OS, as it is easier to grasp the PID of the process spawned
#which can be returned and handled for execution span configurations.
class Macho(object):
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
		os.system("chmod +x " + self.target_sample)

	def _execute(self):
		#The execution process goes here.
		exec_command = "./"+self.target_sample
		target_process = subprocess.Popen([exec_command], shell=False, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
		#fetch target PID
		self.exec_time = time.time()
		self.target_pid = target_process.pid


