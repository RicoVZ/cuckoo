import json
from cuckoo.common.abstracts import BehaviorHandler
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

                            proc_dict = {
                                "type":"process",
                                "pid":json_string["subject"]["pid"],
                                "ppid":json_string["subject"]["ancestors"][0]["exec_pid"],
                                "process_name":"",
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
                                "process_name":"",
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
                                "process_name":"",
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
        except:
            log.warning("Log doesn't contain Xnumon logs.Aborting processing module")
            return False
    except:
        log.warning("Log can't ne parsed by JSON.Aborting processing module")
        return False

