#!/usr/bin/env python3

import requests
import cve_searchsploit
import sys
import os



#the yield returned is converted to the "list" type
def edbid_from_cve(cve):
    return list(iter_edbid_from_cve(cve))

def iter_cve_from_edbid(edb):
    edb = str(int(edb))

    for cve in cve_map:
        if edb in cve_map[cve]:
            yield cve.upper()


#
def searchExploits(cve_id):
    HIGH_CVSS_BOUND = 7.0

    #cve_searchsploit.update_db()

    cve_exploits = set()
    
    edbids = cve_searchsploit.edbid_from_cve(cve_id)
    #print(len(edbids))

    for i in edbids:
        cve_exploits.add(i)

    
    return edbids
    
