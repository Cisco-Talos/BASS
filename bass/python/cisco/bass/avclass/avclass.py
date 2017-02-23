#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
'''
AVClass labeler
'''

from avclass_common import AvLabels
import logging
import os
from pkg_resources import resource_filename

log = logging.getLogger("cisco.bass.avclass")

# Purpose
# Processing data from vt to get category name
# Input dict like :
# {"av_labels": [["Qihoo-360", "HEUR/QVM03.0.Malware.Gen"]], "sha256": "9a17bd521ca2f205dab60bebb90ac2c274139eb099e04ef22f85bbd5322685f9",
# "sha1": "96e65fa5f25386a0eb8c831cbb82c4b19d418ff1", "scan_date": "2016-03-27 00:17:44", "md5": "fe8db83f57ea350f059f4771e52747df"}

class ParseLabels(object):

    def __init__(self):
        self.__default_gen_file = resource_filename("cisco.bass.avclass", 'default.generics')
        self.__default_alias_file = resource_filename("cisco.bass.avclass", 'default.aliases')
        self.__default_category_file = resource_filename("cisco.bass.avclass", 'default.categories')

    def get_family(self, param1):
        """
        get_family will try to compute family name based on data given in param1

        :param param1: lb format {md5,sha1,sha256,scan_date,av_labels}
        :type param1: dict
        :return: string containing family name or SINGLETON
        """

        data = {'unique_name' : '', 'pup' : '', 'category' : ''}

        try:
            av_labels = AvLabels(gen_file=self.__default_gen_file,alias_file= self.__default_alias_file,av_file=None,cat_file= self.__default_category_file)
            self.sample_info = av_labels.get_sample_info(param1, "")
        except Exception, exception:
            log.critical('Error in json loadstrings call: {0}'.format(exception))
            return data

        hash_type='sha256'
        name = getattr(self.sample_info, hash_type)
        family=""
        is_pup_str=""
        category=""
        # Avoiding to return a None object to easily update receptive dict
            # Get the distinct tokens from all the av labels in the report
        try:
            # Get distinct tokens from AV labels
            tokens = av_labels.get_family_ranking(self.sample_info).items()
            # Top candidate is most likely family name
            if tokens:
                family = tokens[0][0]
                if isinstance(family,unicode):
                    family = family.encode('utf-8')
                family= family[0].upper()+family[1:]
            else:
                family = "Generic"
        
            type_malware = av_labels.get_category_ranking(self.sample_info).items()
            category ="Trojan"
            if type_malware:
                category = type_malware[0][0]
            is_pup_str = ""
            # Check if sample is PUP, if requested
            if av_labels.is_pup(self.sample_info[3]):
                is_pup_str = "PUA."
            data = {'unique_name':family, 'pup':is_pup_str, 'category':category}
        except Exception, e:
            log.critical("Error in computing name: {0} - {1}".format(Exception, e))
            pass
        log.debug("Get Family is returning: {0}".format(data))
        return data
