import json
import logging
from cuckoo.common.abstracts import BehaviorHandler

log = logging.getLogger(__name__)
class DarwinXnumonParser(BehaviorHandler):

    key = "processes"

    def __init__(self,path):
        self.matched = False
        self.processes = []

    def handles_path(self,path):
        if path.endswith("xnumon"):
            self.matched = True
            return True

    def parse(self,path):
        if _verify_xnumon(path):
            with open(path) as file:
                for line in file:
                    json_string = json.loads(line)
                    if json_string['eventcode'] == 0 or json_string['eventcode'] == 1:
                        continue
                    else:
                        if json_string['eventcode'] == 2:
                            if not 'reconstructed' in json_string['subject']:
                                proc_dict = {
                                    "type":"process",
                                    "pid":json_string["subject"]["pid"],
                                    "ppid":json_string["subject"]["ancestors"][0]["exec_pid"],
                                    "process_name":json_string['argv'][-1].split('/')[-1],
                                    "first_seen":json_string['image']['ctime'],
                                    "command_line":" ".join(json_string['argv']),
                                    "calls":"",
                                    "path":json_string['image']['path'],
                                    "signature": json_string['image']['signature'],
                                    "origin":json_string['image']['origin']
                                }
                                self.processes.append(proc_dict)
                        elif json_string['eventcode'] == 3:
                            proc_dict = {
                                "type":"process",
                                "pid":json_string["subject"]["pid"],
                                "ppid":json_string["subject"]["ancestors"][0]["exec_pid"],
                                "process_name":json_string['argv'][-1].split('/')[-1],
                                "first_seen":json_string['image']['ctime'],
                                "command_line":" ".join(json_string['argv']),
                                "calls":"",
                                "method":json_string['method'],
                                "path":json_string['image']['path'],
                                "signature": json_string['image']['signature'],
                                "origin":json_string['image']['origin']
                            }
                            self.processes.append(proc_dict)
                        elif json_string['eventcode'] == 4:
                            proc_dict = {
                                "type":"process",
                                "pid":json_string["subject"]["pid"],
                                "ppid":json_string["subject"]["ancestors"][0]["exec_pid"],
                                "process_name":json_string['argv'][-1].split('/')[-1],
                                "first_seen":json_string['image']['ctime'],
                                "command_line":" ".join(json_string['argv']),
                                "calls":"",
                                "daemon":json_string['plist']['path'],
                                "parent_program":json_string['program']['path'],
                                "path":json_string['image']['path'],
                                "signature": json_string['image']['signature'],
                                "origin":json_string['image']['origin']
                            }
                            self.processes.append(proc_dict)
            return self.processes

    def run(self):
        if not self.matched:
            return
        return self.processes

def _verify_xnumon(path):
    log_line = open(path).readline()
    try:
        json_string = json.loads(log_line)
        try:
            if json_string['version']:
                return True
        except Exception as error:
            log.warning("Log doesn't match Xnumon structure: %s",error)
            return False
    except Exception as error:
        log.warning("JSON parsing error: %s", error)
        return False

class DarwinDtraceParser(BehaviorHandler):
    
    key = "darwin_api"

    def __init__(self,path):
        self.matched = False
        self.processes = []

    def handles_path(self,path):
        if path.endswith("dtrace"):
            self.matched = True
            return True

    def parse(self,path):
        if _verify_dtrace(path):
            with open(path) as file:
                for line in file:
                    json_string = json.loads(line)
                    proc_dict = {
                        "type":"open_syscall",
                        "pid":json_string['pid'],
                        "file_path":json_string['file_path'],
                        "open_flag":json_string['flag'],
                    }
                    self.processes.append(proc_dict)
            return self.processes
    
    def run(self):
        if not self.matched:
            return
        return self.processes

def _verify_dtrace(path):
    log_line = open(path).readline()
    try:
        json_string = json.loads(log_line)
        try:
            if json_string['pid']:
                return True
        except Exception as error:
            log.warning("Log doesn't match Dtrace structure: %s",error)
            return False
    except Exception as error:
        log.warning("JSON parsing error: %s", error)
        return False