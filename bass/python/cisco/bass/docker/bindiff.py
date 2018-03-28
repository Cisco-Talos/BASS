# System imports
import itertools
import logging
import json
from collections import defaultdict
import os
import pickle
import tempfile
import subprocess
import shutil
from cisco.bass.binary_database import Database

# Third party imports
import requests

log = logging.getLogger("cisco.bass")


class IdaClient:
    """
    Used for sending commands to one or more IDA containers over HTTP.
    """

    def __init__(self, urls):
        """
        >>> client = Client(['http://host-1:4001', 'http://host-2:4001'])
        :param urls: List of addresses of IDA containers including the published port
        """
        if isinstance(urls, str):
            urls = [urls]
        if urls is None or not any(urls):
            raise ValueError('Invalide "urls" value')
        self._urls = itertools.cycle(urls)

    def bindiff_export(self, sample, is_64_bit = True, timeout = None):
        """
        Load a sample into IDA Pro, perform autoanalysis and export a BinDiff database.
        :param sample: The sample's path
        :param is_64_bit: If the sample needs to be analyzed by the 64 bit version of IDA
        :param timeout: Timeout for the analysis in seconds
        :return: The file name of the exported bindiff database. The file needs
        to be deleted by the caller. Returns None on error.
        """

        data_to_send = {
            "timeout": timeout,
            "is_64_bit": is_64_bit}
        url = "%s/binexport" % next(self._urls)
        log.debug("curl -XPOST --data '%s' '%s'", json.dumps(data_to_send), url)
        response = requests.post(url, data = data_to_send, files = {os.path.basename(sample): open(sample, "rb")})
        if response.status_code == 200:
            handle, output = tempfile.mkstemp(suffix = ".BinExport")
            with os.fdopen(handle, "wb") as f:
                map(f.write, response.iter_content(1024))
            return output
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None

    def pickle_export(self, sample, is_64_bit = True, timeout = None):
        """
        Load a sample into IDA Pro, perform autoanalysis and export a pickle file. 
        :param sample: The sample's path
        :param is_64_bit: If the sample needs to be analyzed by the 64 bit version of IDA
        :param timeout: Timeout for the analysis in seconds
        :return: The file name of the exported pickle database. The file needs
        to be deleted by the caller. Returns None on error.
        """

        data_to_send = {
            "timeout": timeout,
            "is_64_bit": is_64_bit}
        url = "%s/pickle" % next(self._urls)
        log.debug("curl -XPOST --data '%s' '%s'", json.dumps(data_to_send), url)
        response = requests.post(url, data = data_to_send, files = {os.path.basename(sample): open(sample, "rb")})
        if response.status_code == 200:
            handle, output = tempfile.mkstemp(suffix = ".pickle")
            with os.fdopen(handle, "wb") as f:
                map(f.write, response.iter_content(1024))
            return output
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None

    def bindiff_pickle_export(self, sample, is_64_bit = True, timeout = None):
        """
        Load a sample into IDA Pro, perform autoanalysis and export a pickle file. 
        :param sample: The sample's path
        :param is_64_bit: If the sample needs to be analyzed by the 64 bit version of IDA
        :param timeout: Timeout for the analysis in seconds
        :return: The file name of the exported pickle database. The file needs
        to be deleted by the caller. Returns None on error.
        """

        data_to_send = {
            "timeout": timeout,
            "is_64_bit": is_64_bit}
        url = "%s/binexport_pickle" % next(self._urls)
        log.debug("curl -XPOST --data '%s' '%s'", json.dumps(data_to_send), url)
        response = requests.post(url, data = data_to_send, files = {os.path.basename(sample): open(sample, "rb")})
        if response.status_code == 200:
            handle_tar, path_tar = tempfile.mkstemp(suffix = ".tar.gz")
            with os.fdopen(handle_tar, "wb") as f:
                map(f.write, response.iter_content(1024))
            directory = tempfile.mkdtemp()
            subprocess.check_call(["tar", "xf", path_tar], cwd = directory)

            handle_bindiff, output_bindiff = tempfile.mkstemp(suffix = ".BinExport")
            with os.fdopen(handle_bindiff, "wb") as f:
                with open(os.path.join(directory, "output.BinExport"), "rb") as f2:
                    shutil.copyfileobj(f2, f)
            handle_pickle, output_pickle = tempfile.mkstemp(suffix = ".pickle")
            with os.fdopen(handle_pickle, "wb") as f:
                with open(os.path.join(directory, "output.pickle"), "rb") as f2:
                    shutil.copyfileobj(f2, f)
            os.unlink(path_tar)
            shutil.rmtree(directory)
            return output_bindiff, output_pickle
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None


class BindiffClient:
    """
    Used for sending commands to one or more Bindiff containers over HTTP.
    """

    def __init__(self, urls):
        """
        >>> client = Client(['http://host-1:4001', 'http://host-2:4001'])
        :param urls: List of addresses of IDA containers including the published port
        """
        if isinstance(urls, str):
            urls = [urls]
        if urls is None or not any(urls):
            raise ValueError('Invalide "urls" value')
        self._urls = itertools.cycle(urls)

    def compare(self, primary, secondary, timeout = None):
        """
        Run BinDiff on the two BinDiff databases.
        :param primary: The first BinExport database
        :param secondary: The second BinExport database
        :param timeout: Timeout for the command in seconds
        :returns: The directory name of the directory with the generated data on the shared volume
        """

        url = "%s/compare" % next(self._urls)
        log.debug("curl -XPOST --form 'timeout=%s' --form 'primary=@%s' --form 'secondary=@%s' '%s'", str(timeout), primary, secondary, url)
        response = requests.post(url, data = {"timeout": timeout}, \
                files = {"primary": open(primary, "rb"), "secondary": open(secondary, "rb")})

        if response.status_code == 200:
            handle, path = tempfile.mkstemp(suffix = ".bindiff.sqlite3")
            with os.fdopen(handle, "wb") as f:
                map(f.write, response.iter_content(1024))
            return path
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None
