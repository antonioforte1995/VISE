#!/usr/bin/env python3
from elasticsearch import Elasticsearch
import os

es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@localhost:9200"

#this function returns an array of CPEs matching our searched products
#this array contains the CPE json objects
def search_CPEs(product_name, version_number, vendor_name, target_software, product_type):

    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cpe-index", body={
        "query": {
            "bool": {
                "should": [
                    {
                        "regexp": {
                            "cpe23Uri.keyword": {
                                "value": "cpe:2.3:"+product_type+":"+ vendor_name +":"+ product_name +":"+ version_number +":.*:.*:.*:.*:"+ target_software +":.*:.*",
                                "boost": 1.0
                            }
                        }
                    },
                    {
                        "regexp": {
                            "cpe_name.cpe23Uri.keyword": {
                                "value": "cpe:2.3:"+product_type+":"+ vendor_name +":"+ product_name +":"+ version_number +":.*:.*:.*:.*:"+ target_software +":.*:.*",
                                "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    },size=1000)
    cpes = res['hits']['hits']
    return cpes


#this function is used to search the CVE associated to a cpe23Uri when the corresponding CPE json object
#specifies a single limit of version (es. versionStartIncluding)
#version_type is the type of version limit (es. versionStartIncluding)
#version is the value of this version limit
def search_CVE_from_single_limit(cpe23Uri_to_submit, children = ""):
    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cve-index", body={
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "vuln.nodes{0}.cpe_match.cpe23Uri.keyword".format(children): {
                            "value": cpe23Uri_to_submit['cpe23Uri'],
                            "boost": 1.0
                            }
                        }
                    },
                    {
                        "term": {
                            "vuln.nodes{0}.cpe_match.{1}.keyword".format(children, cpe23Uri_to_submit['version_types'][0]): {
                            "value": cpe23Uri_to_submit['version_types_values'][0],
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    },size=1000)
    cves = res['hits']['hits']
    return cves


#this function is used to search the CVE associated to a cpe23Uri when the corresponding CPE json object
#specifies an version interval (es. versionStartIncluding and versionEndExcluding)
#version_types is the array with the limits of the range (es. versionStartIncluding and versionEndExcluding)
#version_start is the value of the first limit
#version_end is the value of the second limit
def search_CVE_from_interval(cpe23Uri_to_submit, children = ""):

    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cve-index", body={
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "vuln.nodes{0}.cpe_match.cpe23Uri.keyword".format(children): {
                            "value": cpe23Uri_to_submit['cpe23Uri'],
                            "boost": 1.0
                            }
                        }
                    },
                    {
                        "term": {
                            "vuln.nodes{0}.cpe_match.{1}.keyword".format(children, cpe23Uri_to_submit['version_types'][0]): {
                            "value": cpe23Uri_to_submit['version_types_values'][0],
                            "boost": 1.0
                            }
                        }
                    },
                    {
                        "term": {
                            "vuln.nodes{0}.cpe_match.{1}.keyword".format(children, cpe23Uri_to_submit['version_types'][1]): {
                            "value": cpe23Uri_to_submit['version_types_values'][1],
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    },size=1000)
    cves = res['hits']['hits']
    return cves


#this function is used to search the CVE associated to a cpe23Uri when the corresponding CPE json object
#specifies a specific version
def search_CVE(cpe23Uri): 
    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cve-index", body={
        "query": {
            "bool": {
                "should": [
                    {
                        "term": {
                            "vuln.nodes.cpe_match.cpe23Uri.keyword": {
                            "value": cpe23Uri,
                            "boost": 1.0
                            }
                        }
                    },
                    {
                        "term": {
                            "vuln.nodes.children.cpe_match.cpe23Uri.keyword": {
                            "value": cpe23Uri,
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    },size=1000)
    cves = res['hits']['hits']
    return cves