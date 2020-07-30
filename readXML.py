#!/usr/bin/env python3
import xlrd
from queries import *
from enrichment import *
import os
  

workbook = xlrd.open_workbook('/home/antonio/Scrivania/VIS3/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)

cve_all_edbids = set()


def search_exploits(row):
    os.system('searchsploit '+ worksheet.cell_value(row,3) + ' ' + worksheet.cell_value(row,1) +  ' ' + worksheet.cell_value(row,5) + ' -w')
    os.system('searchsploit '+ worksheet.cell_value(row,3) + ' ' + worksheet.cell_value(row,1) +  ' ' + 'Multiple -w')
    

for row in range(worksheet.nrows-3, worksheet.nrows-2):
    cpes = search_CPE(worksheet.cell_value(row,4), worksheet.cell_value(row,0), worksheet.cell_value(row,1), worksheet.cell_value(row,5))
    vett_cpe23Uri = [0]*len(cpes)
    vett_versionStartIncluding = [0]*len(cpes)
    vett_versionStartExcluding = [0]*len(cpes)
    vett_versionEndIncluding = [0]*len(cpes)
    vett_versionEndExcluding = [0]*len(cpes)

    #pprint(cpes)


    if (len(cpes) > 0):
        for i in [0, len(cpes)-1]:
            print("")
            vett_cpe23Uri[i] = cpes[i]["_source"]["cpe23Uri"]
            if "versionStartIncluding" in cpes[i]["_source"]:
                vett_versionStartIncluding[i] = cpes[i]["_source"]["versionStartIncluding"]
            else:
                vett_versionStartIncluding[i] = ""
            if "versionStartExcluding" in cpes[i]["_source"]:
                vett_versionStartExcluding[i] = cpes[i]["_source"]["versionStartExcluding"]
            else: 
                vett_versionStartExcluding[i] = ""
            if "versionEndIncluding" in cpes[i]["_source"]:
                vett_versionEndIncluding[i] = cpes[i]["_source"]["versionEndIncluding"]
            else:
                vett_versionEndIncluding[i] = ""
            
            if "versionEndExcluding" in cpes[i]["_source"]:
                vett_versionEndExcluding[i] = cpes[i]["_source"]["versionEndExcluding"]
            else:
                vett_versionEndExcluding[i] = ""
            
            print('cpe23Uri: {0}'.format(vett_cpe23Uri[i]) )     
            print('VersionStartIncluding: {0}'.format(vett_versionStartIncluding[i]))
            print('VersionStartExcluding: {0}'.format(vett_versionStartExcluding[i]))
            print('vett_versionEndIncluding: {0}'.format(vett_versionEndIncluding[i]))
            print('vett_versionEndExcluding: {0}'.format(vett_versionEndExcluding[i]))


            cves = search_CVE( vett_cpe23Uri[i], vett_versionStartIncluding[i], vett_versionStartExcluding[i], vett_versionEndIncluding[i], vett_versionEndExcluding[i])
        #search_exploits(row)
    
    
    for cve_all in cves:
        #print(cve_all["_id"])
        stampaInfo(cve_all)
        
    """
        cve_edbids = searchExploits(cve_all["_id"])
        for i in cve_edbids:
            cve_all_edbids.add(i)
    
    print("All Edbids for all CVE: {0}".format(cve_all_edbids)) 
    

    for i in cve_all_edbids:
            os.system('searchsploit '+ str(i) + ' -w')
    print()
    """
    pass