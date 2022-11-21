import hashlib
import platform
from flask import session


def get_dir_by_os():
    system = platform.system()
    dir = "/opt/SGDF"
    if system == "Windows":
        dir = "C:\SGDF"
    elif system == "Linux":
        dir = "/opt/SGDF"
    return dir


def hash_file(filename):
    """"This function returns the SHA256 hash
    of the file passed into it"""
    h = hashlib.sha256()
    with open(filename, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()


def is_logged():
    username = session.get("username")
    access = session.get("access")
    if username is None or not access:
        return False
    return True


def write_permission():
    write = session.get("write")
    if not write:
        return False
    return True


def read_permission():
    read = session.get("read")
    if not read:
        return False
    return True


def remove_permission():
    remove = session.get("remove")
    if not remove:
        return False
    return True
