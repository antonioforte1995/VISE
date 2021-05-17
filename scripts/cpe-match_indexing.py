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

# connect to Elasticsearch host
# timeout is time in seconds to keep Elasticsearch client connection open
es = Elasticsearch([es_url], timeout = 30000)

class CPE:

    def __init__(self):
        self.ids = []
        self.current = -1

    def add(self, i, id):
        # Bulk inserting is a way to add multiple documents to Elasticsearch in a single request
        cpe_bulk = {
                    # the action is update
                    "_op_type": "update",
                    "_index":   "cpe-index",
                    "_id":      id,
                    # doc_as_upsert is used to update a document
                    "doc_as_upsert": True,
                    "doc":  i
                   }
        # append new bulk to ids
        self.ids.append(cpe_bulk)

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
                    # Elasticsearch divides the data into different shards (unit) around the cluster
                    "number_of_shards" :3,
                    "index":{
                        "analysis":{
                        # we define the analyzer_shingle analyzer for both search and index
                        "analyzer":{
                            "analyzer_shingle":{
                                # analyzer first applies the standard tokenizer, then walks through the standard, lowercase and filter_stop filters 
                                "tokenizer":"standard",
                                "filter":["lowercase", "filter_stop"]
                            }
                        },
                        "filter":{
                            "filter_stop":{
                                "type":"stop"
                            }
                        }
                    }
                }
            },
            # Mapping is the process of defining how a document, and the fields it contains, are stored and indexed
            "mappings": {
                # properties object holds the list of fields and their type
                "properties": {
                    "matches": {
                        # the nested type is a data type that allows to index arrays of objects and to maintain the independence of each object in the array
                        "type" : "nested"
                    }
                }
            }
            }
        )

    fh = open(input_file)
    #  takes a file object and returns the json object
    json_data = json.load(fh)

    # the_cpes is the iterable object
    the_cpes = CPE()

    id = 0
    # for each dictionary in matches list call the add(i, id) function to the_cpes iterable object
    # i is the current dictionary
    # id is the id of the dictionary in the the_cpes object
    for i in json_data['matches']:
        id = id + 1
        the_cpes.add(i, id)

    #streaming_bulk(c) won't actually do anything. It's not until you iterate over it 
    #as is done in this for loop that the indexing actually starts to happen.
    # the_cpes is the iterable containing the actions to be executed
    # max_retries is the maximum number of times a document will be retried
    for ok, item in elasticsearch.helpers.streaming_bulk(es, the_cpes, max_retries=2):
            if not ok:
                print("ERROR:")
                print(item)

if __name__ == "__main__":
    main()