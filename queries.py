#!/usr/bin/python3

from pprint import pprint
from elasticsearch import Elasticsearch
import os

es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@3.225.242.97:9200"


def search_CPE(vendor, product, version, target_software):

    if (target_software == ""):
        target_software = ".*"

    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cpe-index", body={
        "query": {
            "bool": {
                "should": [
                    {
                        "regexp": {
                            "cpe23Uri.keyword": {
                                "value": "cpe:2.3:a:"+ vendor +":"+ product +":"+ version +":.*:.*:.*:.*:(*|"+ target_software +"):.*:.*",
                                "boost": 1.0
                            }
                        }
                    },
                    {
                        "regexp": {
                            "cpe_name.cpe23Uri.keyword": {
                                "value": "cpe:2.3:a:"+ vendor +":"+ product +":"+ version +":.*:.*:.*:.*:(*|"+ target_software +"):.*:.*",
                                "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    }, size=10000)
    cpes = res['hits']['hits']
    return cpes



def search_CVE_from_single_limit(cpe23Uri, version_type, version):
    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cve-index", body={
        "query": {
            "bool": {
                "must": [
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
                            "vuln.nodes.cpe_match.{0}.keyword".format(version_type): {
                            "value": version,
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    }, size=10000)
    cves = res['hits']['hits']
    return cves



def search_CVE_from_interval(cpe23Uri, versions_types, version_start, version_end):
    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cve-index", body={
        "query": {
            "bool": {
                "must": [
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
                            "vuln.nodes.cpe_match.{0}.keyword".format(versions_types[0]): {
                            "value": version_start,
                            "boost": 1.0
                            }
                        }
                    },
                    {
                        "term": {
                            "vuln.nodes.cpe_match.{0}.keyword".format(versions_types[1]): {
                            "value": version_end,
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    }, size=10000)
    cves = res['hits']['hits']
    return cves


def search_CVE(cpe23Uri):
    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cve-index", body={
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "vuln.nodes.cpe_match.cpe23Uri.keyword": {
                            "value": cpe23Uri,
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    }, size=10000)
    cves = res['hits']['hits']
    return cves



def stampaInfo(cve):
    print("")
    print("")
    print("--------------")
    print(cve['_id'])
    #return
    print("Metrics:")
    cve = cve['_source']
    #pprint(cve['baseMetricV2']['cvssV2'])
    for key, val in cve['baseMetricV2'].items():
        if "obtain" in key:
            print(key, " -> ", val)
    print("Score: ", cve['baseMetricV2']['impactScore'])
    print("Severity: ", cve['baseMetricV2']['severity'])
    desc = cve['description']['description_data']
    print("")
    print("Description:")
    for d in desc:
        if 'en' in d['lang']:
            print(''.join(d['value']))
            break
    print("")
    print("References:")
    pprint(cve['references']['reference_data'])
    print("")
    print("Vulnerable configurations:")
    pprint(cve['vuln'])
    print("--------------")
    print("")