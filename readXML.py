#!/usr/bin/env python3
import xlrd
from queries import *
from enrichment import *
import os
  

workbook = xlrd.open_workbook('/home/antonio/Scrivania/VIS3/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)

cves = []
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
        for i in range(0, len(cpes)):
            not_null_version_types = 0
            versions_types = []
            versions_types_values = []

            print("")
            vett_cpe23Uri[i] = cpes[i]["_source"]["cpe23Uri"]
            print('cpe23Uri: {0}'.format(vett_cpe23Uri[i]))
            
            if "versionStartIncluding" in cpes[i]["_source"]:
                vett_versionStartIncluding[i] = cpes[i]["_source"]["versionStartIncluding"]
                not_null_version_types = not_null_version_types + 1
                versions_types.append("versionStartIncluding") 
                versions_types_values.append(cpes[i]["_source"]["versionStartIncluding"])

            if "versionStartExcluding" in cpes[i]["_source"]:
                vett_versionStartExcluding[i] = cpes[i]["_source"]["versionStartExcluding"]
                not_null_version_types = not_null_version_types + 1
                versions_types.append("versionStartExcluding")
                versions_types_values.append(cpes[i]["_source"]["versionStartExcluding"])

            if "versionEndIncluding" in cpes[i]["_source"]:
                vett_versionEndIncluding[i] = cpes[i]["_source"]["versionEndIncluding"]
                not_null_version_types = not_null_version_types + 1
                versions_types.append("versionEndIncluding")
                versions_types_values.append(cpes[i]["_source"]["versionEndIncluding"])
            
            if "versionEndExcluding" in cpes[i]["_source"]:
                vett_versionEndExcluding[i] = cpes[i]["_source"]["versionEndExcluding"]
                not_null_version_types = not_null_version_types + 1
                versions_types.append("versionEndExcluding")
                versions_types_values.append(cpes[i]["_source"]["versionEndExcluding"])

            #print('cpe23Uri: {0}'.format(vett_cpe23Uri[i]))   
            #print('NotNullVersionTypes: {0}'.format(not_null_version_types)) 
            #print('VersionTypes: {0}'.format(versions_types)) 

            if (len(versions_types) == 1):
                cves.append(search_CVE_from_single_limit(vett_cpe23Uri[i], versions_types[0], versions_types_values[0]))
            elif (len(versions_types) == 2):
                cves.append(search_CVE_from_interval(vett_cpe23Uri[i], versions_types, versions_types_values[0], versions_types_values[1]))
            else:
                cves.append(search_CVE(vett_cpe23Uri[i]))
            
            


            #cves = search_CVE( vett_cpe23Uri[i], vett_versionStartIncluding[i], vett_versionStartExcluding[i], vett_versionEndIncluding[i], vett_versionEndExcluding[i])
        #search_exploits(row)
    

    
    for cve in cves:
        print(cve[0]["_id"])
        #stampaInfo(cve[0])
        
    
        cve_edbids = searchExploits(cve[0]["_id"])
        for i in cve_edbids:
            cve_all_edbids.add(i)
    
    print("All Edbids for all CVE: {0}".format(cve_all_edbids)) 
    

    for i in cve_all_edbids:
            os.system('searchsploit '+ str(i) + ' -w')
    print()
    
    pass