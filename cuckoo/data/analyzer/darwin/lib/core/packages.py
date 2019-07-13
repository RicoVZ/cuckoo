import inspect
from sets import Set
from os import sys, path

def _initiate_recognition(file_type, file_name, suggestion=None, package_path=None):
    #path received as package_path
    if suggestion is not None:
        name = suggestion
    else:
        name = _guess_package_name(file_type, file_name)
        if not name:
            return None

    full_name = "modules.packages.%s" % name
    try:
        #Acquire the full path to be imported.
        sys.path.append(path.abspath(path.join(path.dirname(__file__), '..', '..')))
        #Import every memeber of the module.
        module = __import__(full_name, globals(), locals(), ['*'])
    except ImportError:
        raise Exception("Unable to import package \"{0}\": it does not "
                        "exist.".format(name))
    try:
        package_class = _found_target_class(module, name)
    except IndexError as err:
        raise Exception("Unable to select package class (package={0}): "
                        "{1}".format(full_name, err))
    #Pass the sample to the class for further execution
    exec_sample = package_class(package_path)
    #Return the PID of the process spawned and execution time
    return exec_sample.target_pid, exec_sample.exec_time


def _found_target_class(module, name):
    #Determine the class_name --> Capitalised version of name
    members = inspect.getmembers(module, inspect.isclass)
    return [x[1] for x in members if x[0] == name.capitalize()][0]


def _guess_package_name(file_type, file_name):
    if "Bourne-Again" in file_type or "bash" in file_type:
        return "bash"
    elif "Mach-O" in file_type and "executable" in file_type:
        return "macho"
    elif "directory" in file_type and (file_name.endswith(".app") or file_name.endswith(".app/")):
        return "app"
    elif "ASCII" in file_type or "text" in file_type and file_name.endswith(".py"):
        return "python"
    elif file_name.endswith(".pkg"):
        return "packages"
    else:
        return None

