#!/usr/bin/env python3
from elasticsearch import Elasticsearch
import os

es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@localhost:9200"

# this function returns a list of CPEs matching a searched_cpe23Uri
# each CPE is a json object
def search_CPEs(searched_cpe23Uri):

    es = Elasticsearch(hosts=[es_url])

    res = es.search(index="cpe-index", body={
        "query": {
            "bool": {
                "should": [
                    {
                        "regexp": {
                            "cpe23Uri.keyword": {
                                "value": searched_cpe23Uri,
                                "boost": 1.0
                            }
                        }
                    },
                    {
                        "regexp": {
                            "cpe_name.cpe23Uri.keyword": {
                                "value": searched_cpe23Uri,
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


# this function returns a list of CVEs matching:
# 1) a searched_cpe23Uri 
# 2) a specific version_type (e.g. versionStartIncluding)
# 3) a specific version_type_value
def search_CVEs_from_single_limit(cpe23Uri_to_submit, children = ""):
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


# this function returns a list of CVEs matching:
# 1) a searched_cpe23Uri 
# 2) a specific start limit of version range (e.g. versionStartIncluding)
# 3) a specific start limit value of version range
# 4) a specific end limit of version range (e.g. versionEndIncluding)
# 5) a specific end limit value of version range
def search_CVEs_from_interval(cpe23Uri_to_submit, children = ""):

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


# this function returns a list of CVEs matching a searched_cpe23Uri that specifies a specific version
def search_CVEs(cpe23Uri): 
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