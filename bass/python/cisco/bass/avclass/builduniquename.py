import logging
import os
import json
import pprint
from pkg_resources import resource_stream

log = logging.getLogger("cisco.bass.avclass")

from avclass import ParseLabels

class ComputeVtUniqueName:
    def __init__(self):
        self.debug_json_file = 'debug_vt.json'
        self.info_hash = {}
        self.list_hashes = []
        self.data = []
        self.__labels = ParseLabels()

        # Loading file containing aliases for Clamav
        try:
            with resource_stream("cisco.bass.avclass", "vt_platform.json") as data:
                self.vt_platform = json.load(data)
                log.debug('platform file load vt is :{0}'.format(pprint.pformat(self.vt_platform)))
            data.close()
        except IOError:
            log.critical('Data file for vt platform is missing')
            pass

        try:
            with resource_stream("cisco.bass.avclass", "si_platform.json") as data:
                self.si_platform = json.load(data)
                log.debug('platform file load si is :{0}'.format(pprint.pformat(self.si_platform)))
            data.close()
        except IOError:
            log.critical('Data file for si platform is missing')
            pass

        try:
            with resource_stream("cisco.bass.avclass", 'archives.json') as data:
                self.archive_mimetype = json.load(data)
                log.debug('archiving mimetype is :{0}'.format(pprint.pformat(self.archive_mimetype)))
            data.close()
        except IOError:
            log.critical('Archive mimetype file is missing')
            pass

        try:
            with resource_stream("cisco.bass.avclass", 'vt_type.json') as data:
                self.vt_type = json.load(data)
                log.debug('type from vt are :{0}'.format(pprint.pformat(self.vt_type)))
            data.close()
        except IOError:
            log.critical('Type Vt file is missing')
            pass

        try:
            with resource_stream("cisco.bass.avclass", 'vt_tags.json') as data:
                self.vt_tags = json.load(data)
                log.debug('tags from vt are :{0}'.format(pprint.pformat(self.vt_tags)))
            data.close()
        except IOError:
            log.critical('Tags Vt file is missing')
            pass

    def build_unique_name(self, vt_data_record = {}):
        self.records = {}
        results = self.__gather_data(vt_data_record)
        return results

    def __gather_data(self, vt_record = {}):
        vt_data_record = vt_record.get('results',None)
        if vt_data_record is None:
            return None

        if vt_data_record.get('response_code', 0):
            self.record = {'sha1': vt_data_record.get('sha1', None), 'md5': vt_data_record.get('md5', None),
                           'sha256': vt_data_record.get('sha256', None),
                           'scan_date': vt_data_record.get('scan_date', None),
                           'av_labels': [[k, v['result']] for k, v in vt_data_record['scans'].iteritems() if
                                         'scans' in vt_data_record and 'result' in v and v['result']]}
            signature = self.__labels.get_family(self.record)
            # Todo: Check if signature contains platform
            if vt_data_record.get('type', '') :
                # If we cannot identify type from vt, looks at tags
                platform = self.__identify_platform(vt_data_record['type'])
                if not platform:
                    for el in vt_data_record['tags']:
                        platform = self.__identify_platform(el)
                        if platform:
                            break
                if platform:
                    signature['platform'] = platform
                else:
                    # By default we said it's a windows one
                    signature['platform']  = 'Win'
            else:
                signature['platform'] = 'Win'
        return signature

    def __identify_platform(self, string_identifier):
        log.debug("Trying to identify platform with : {0}".format(string_identifier))
        if string_identifier in self.vt_platform:
            return (self.vt_platform[string_identifier])
        if string_identifier in self.vt_type:
            return (self.vt_type[string_identifier])
        if string_identifier in self.vt_tags:
            return (self.vt_tags[string_identifier])
        if string_identifier in self.si_platform:
            return (self.si_platform[string_identifier])
        return ''
