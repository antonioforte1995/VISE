#!/usr/bin/python3

from pprint import pprint
from elasticsearch import Elasticsearch

es_url = "http://elastic:changeme@3.225.242.97:9200"

def search_all_CVE(cpe):
    es = Elasticsearch(hosts=[es_url])
    t = cpe.split(":", 13)
    if t[2] not in "aoh":
        t[2] = "[aoh]"
    if t[3] == "*":
        t[3] = "[^:]+"
    for i in range(len(t)):
        if "." in t[i]:
            #Sostituire . con \\.
            t[i] = t[i].replace(".", "\\.")
            pass
        if "*" == t[i] and i > 5:
            t[i] = "\\*"
        if (i == 5 or i >= 9) and t[i] != "\\*":
            t[i] = "(\\*|(" + t[i] + "))"
        elif (i >= 6 and t[i] == "\\*"):
            t[i] = "(\\*|(" + "[^:]+" + "))"
    #print(':'.join(t))
    if len(t) != 13:
        #print(len(t))
        t.append(".*")
    cpe_without_version = ':'.join(t)
    #toCheck = "cpe:2\\.3:a:paloaltonetworks:globalprotect:(\\*|(5\\.0\\.0)):\\*:\\*:\\*:\\*:(\\*|(windows)):\\*:\\*"
    #toCheck = "cpe:2\\.3:a:paloaltonetworks:globalprotect:(\\*|(5\\.0\\.0)):\\*:\\*:\\*:\\*:(\\*|(windows)):\\*:\\*"
    print(cpe_without_version)
    #print(toCheck)
    #return []
    #GET cve-index/_search
    #"query"...
    res = es.search(index="cve-index", body={
        "query": {
            "regexp": {
                "vuln.nodes.cpe_match.cpe23Uri.keyword": cpe_without_version
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
    #demoCPE = "cpe:2.3:a:paloaltonetworks:globalprotect:5.0.0:*:*:*:*:windows:*:*"
    #demoCPE = "cpe:2.3:*:*:easycreate:3.2.1:*"
    cves = search_all_CVE(demoCPE)
    for cve_all in cves:
        stampaInfo(cve_all)
