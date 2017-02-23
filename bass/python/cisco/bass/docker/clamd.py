import itertools
import requests
import tempfile
import subprocess
import os

class Client():
    def __init__(self, urls = ["http://localhost:5000"]):
        self.urls = itertools.cycle(urls) 

    def ping(self):
        resp = requests.get("%s/ping" % self.urls.next())
        if resp.status_code == 200 and "ok" in resp.json() and resp.json()["ok"]:
            return True
        else:
            return False

    def version(self):
        resp = requests.get("%s/version" % self.urls.next())
        if resp.status_code == 200 and "version" in resp.json():
            return resp.json()["version"]
        else:
            return None

    def reload(self):
        resp = requests.post("%s/reload" % self.urls.next())
        if resp.status_code == 200 and "message" in resp.json() and resp.json()["message"] == "RELOADING":
            return True
        else:
            return False

    def _scan_file(self, url_path, paths):
        if isinstance(paths, str):
            paths = [paths]

        files = dict((path, open(path, "rb")) for path in paths)
        resp = requests.post("%s/%s" % (self.urls.next(), url_path), files = files)
        if resp.status_code == 200:
            return resp.json()
        else:
            return False

    def scan_file(self, paths):
        return self._scan_file("scan_file", paths)

    def multiscan_file(self, paths):
        return self._scan_file("multiscan_file", paths)

    def contscan_file(self, paths):
        return self._scan_file("contscan_file", paths)

    def unpack(self, path):
        resp =requests.post("%s/unpack" % self.urls.next(), files = {"file": open(path, "rb")})
        if resp.status_code == 200:
            handle, tarname = tempfile.mkstemp()
            with os.fdopen(handle, "wb") as f:
                for chunk in resp.iter_content(1024):
                    f.write(chunk)
            dirname = tempfile.mkdtemp()
            subprocess.check_call(["tar", "xzf", tarname, "-C", dirname])
            os.unlink(tarname)
            return dirname
        else:
            return None
            
        
