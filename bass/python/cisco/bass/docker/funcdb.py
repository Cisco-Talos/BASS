import requests
import pickle
from io import BytesIO

def _filter_functions(fns, **kwargs):
    if "functions" in kwargs:
        return [f for f in fns if f["name"] in kwargs["functions"]]
    elif "entry_points" in kwargs:
        return [f for f in fns if f["entry_point"] in kwargs["entry_points"]]
    else:
        return fns

class FuncDB(object):
    def __init__(self, url):
        self.url = url

    def add(self, db, **kwargs):
        db_data = db.data.copy()
        db_data["functions"] = _filter_functions(db.data["functions"], **kwargs)
        data = pickle.dumps(db_data)
        result = requests.post("{:s}/function".format(self.url), files = {"file": BytesIO(data)})
        if result.status_code != 200:
            raise RuntimeError("Request failed with status code {:d}".format(result.status_code))

    def find_raw(self, db, **kwargs):
        db_data = db.data.copy()
        db_data["functions"] = _filter_functions(db.data["functions"], **kwargs)
        data = pickle.dumps(db_data)
        result = requests.post("{:s}/function/find/raw".format(self.url), files = {"file": BytesIO(data)})
        if result.status_code == 200:
            return True
        elif result.status_code == 404:
            return False
        else:
            raise RuntimeError("Request failed with status code {:d}".format(result.status_code))

    def find_mnem(self, db, **kwargs):
        db_data = db.data.copy()
        db_data["functions"] = _filter_functions(db.data["functions"], **kwargs)
        data = pickle.dumps(db_data)
        result = requests.post("{:s}/function/find/mnem".format(self.url), files = {"file": BytesIO(data)})
        if result.status_code == 200:
            return True
        elif result.status_code == 404:
            return False
        else:
            raise RuntimeError("Request failed with status code {:d}".format(result.status_code))




