#!/usr/bin/python3

'''
This script creates cpe-match index on Elasticsearch
'''

import sys
import json
import os
import urllib.request
import elasticsearch
import elasticsearch.helpers
from elasticsearch import Elasticsearch

if 'ESURL' not in os.environ:
    es_url = "http://elastic:changeme@localhost:9200"
else:
    es_url = os.environ['ESURL']

es = Elasticsearch([es_url], timeout = 30000)

class CPE:

    def __init__(self):
        self.ids = []
        self.current = -1
        self.rh_data = None

    def add(self, i, id):
        cpeURI = i['cpe23Uri']
        #cpeName = i['cpe_name']
        cve_bulk = {
                    "_op_type": "update",
                    "_index":   "cpe-index",
                    "_id":      id,
                    "doc_as_upsert": True,
                    "doc":  i
                   }

        self.ids.append(cve_bulk)

    def __next__(self):
        "Handle a call to next()"

        self.current = self.current + 1
        if self.current >= len(self.ids):
            raise StopIteration

        return self.ids[self.current]

    def __iter__(self):
        return self

    def __len__(self):
        return len(self.ids)

    def __get_redhat_data(self, the_cve):

        if self.rh_data is None:

            self.rh_data = {}

            fh = open('data/cve_dates.txt')
            for line in fh.readlines():
                line = line.rstrip()

                # The data format looks like
                # CVE key=value,key=value,...
                split_line = line.split(' ')
                cve = split_line[0]
                self.rh_data[cve] = {}

                if len(split_line) > 1:
                    # There are a few CVE IDs that don't have any data
                    data = split_line[1]
                else:
                    next

                for keyval in data.split(','):
                    (key, value) = keyval.split('=')
                    if key == 'cvss3' or key == 'cvss2':
                        # The cvss scores are special, we only want the
                        # number
                        value = float(value.split('/')[0])
                    self.rh_data[cve][key] = value

        if the_cve in self.rh_data:
            return self.rh_data[the_cve]
        else:
            return {}



def main():

    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        print("Usage: %s <nvd-xml-file>" % (sys.argv[0]))
        sys.exit(1)

    # First let's see if the index exists
    if es.indices.exists('cpe-index') is False:
        # We have to create it and add a mapping
        es.indices.create(
            index="cpe-index",
            body={
                "settings":{
                    "number_of_shards" :3,
                    "index":{
                        "analysis":{
                        "analyzer":{
                            "analyzer_shingle":{
                                "tokenizer":"standard",
                                "filter":["lowercase", "filter_stop", "filter_shingle"]
                            }
                        },
                        "filter":{
                            "filter_shingle":{
                                "type":"shingle",
                                "max_shingle_size":3,
                                "min_shingle_size":2,
                                "output_unigrams":"true"
                            },
                            "filter_stop":{
                                "type":"stop"
                            }
                        }
                    }
                }
            },
            "mappings": {
                "properties": {
                    "matches": {
                        "type" : "nested"
                    }
                }
            }
            }
        )

    fh = open(input_file)
    json_data = json.load(fh)

    the_cpes = CPE()

    id = 0
    for i in json_data['matches']:
        # ['CVE_Items'][0]['cve']['CVE_data_meta']['ID']
        id = id + 1
        the_cpes.add(i, id)
        #es.update(id=cve_id, index="cve-index", body={'doc' : cve, 'doc_as_upsert': True})


    for ok, item in elasticsearch.helpers.streaming_bulk(es, the_cpes, max_retries=2):
            if not ok:
                print("ERROR:")
                print(item)

if __name__ == "__main__":
    main()
