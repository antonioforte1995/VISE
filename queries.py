#!/usr/bin/python3

from pprint import pprint
from elasticsearch import Elasticsearch

es_url = "http://elastic:changeme@3.225.242.97:9200"


def search_CPE(vendor, product, version, target_software):
    """
    print('VENDOR: {0}'.format(vendor))
    print('PRODUCT: {0}'.format(product))
    print('VERSION: {0}'.format(version))
    print('TARGET_SOFTWARE: {0}'.format(target_software))
    """

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
    #pprint(res)
    cpes = res['hits']['hits']
    print("Number of CPE: {0}".format(len(cpes)))
    return cpes



def search_CVE_from_single_limit(cpe23Uri, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding):
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
                            "vuln.nodes.cpe_match.versionStartIncluding.keyword": {
                            "value": versionStartIncluding,
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    }, size=10000)
    #pprint(res)
    cves = res['hits']['hits']
    print("Number of CVE: {0}".format(len(cves)))
    return cves



def search_CVE_from_interval(cpe23Uri, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding):
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
                            "vuln.nodes.cpe_match.versionEndIncluding.keyword": {
                            "value": versionEndIncluding,
                            "boost": 1.0
                            }
                        }
                    }
                ]
            }
        }
    }, size=10000)
    #pprint(res)
    cves = res['hits']['hits']
    print("Number of CVE: {0}".format(len(cves)))
    return cves


def stampaInfo(cve_all):
    print(cve_all['_id'])
    #return
    print("Metrics:")
    cve = cve_all['_source']
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

if __name__ == "__main__":
    cves = search_all_CVE(demoCPE)
    for cve_all in cves:
        stampaInfo(cve_all)