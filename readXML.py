#!/usr/bin/env python3
import xlrd
from queries import *
from enrichment import *
import os
import prettytable
from prettytable import ALL as ALL
  

workbook = xlrd.open_workbook('/home/antonio/Scrivania/VIS3/SearchingCard.xlsx', on_demand = True)
#workbook = xlrd.open_workbook('/home/giampaolo/Desktop/VIS3/VIS3/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)

cves = []
cve_all_edbids = set()


x = prettytable.PrettyTable(hrules=ALL)
x.field_names = ["CPE", "CVE", "CVSS", "CWE", "URLs"]


def setup_cli_table():
    for f in x.field_names:
        x.align[f] = "l"

def format_description(description, max_line_length):
    #accumulated line length
    ACC_length = 0
    words = description.split(" ")
    formatted_description = ""
    for word in words:
        #if ACC_length + len(word) and a space is <= max_line_length 
        if ACC_length + (len(word) + 1) <= max_line_length:
            #append the word and a space
            formatted_description = formatted_description + word + " "
            #length = length + length of word + length of space
            ACC_length = ACC_length + len(word) + 1
        else:
            #append a line break, then the word and a space
            formatted_description = formatted_description + "\n" + word + " "
            #reset counter of length to the length of a word and a space
            ACC_length = len(word) + 1
    return formatted_description

def colorize(string, color=None, highlight=None, attrs=None):
    """Apply style on a string"""
    # Colors list: https://pypi.org/project/colored/
    return colored.stylize(
        string,
        (colored.fg(color) if color else "")
        + (colored.bg(highlight) if highlight else "")
        + (colored.attr(attrs) if attrs else ""),
    )

def color_cvss(cvss):
    """Attribute a color to the CVSS score"""
    cvss = float(cvss)
    if cvss < 3:
        color = "green_3b"
    elif cvss <= 5:
        color = "yellow_1"
    elif cvss <= 7:
        color = "orange_1"
    elif cvss <= 8.5:
        color = "dark_orange"
    else:
        color = "red"
    return color


def format_URLs(URLs, max_line_length):
    #accumulated line length
    URLs = URLs.replace("[", '')
    URLs = URLs.replace("'", '')
    URLs = URLs.replace("]", '')
    ACC_length = 0
    words = URLs.split(", ")
    formatted_URLs = ""
    for word in words:
        #if ACC_length + len(word) and a space is <= max_line_length 
        if ACC_length + (len(word) + 1) <= max_line_length:
            #append the word and a space
            formatted_URLs = formatted_URLs + word + " "
            #length = length + length of word + length of space
            ACC_length = ACC_length + len(word) + 1
        else:
            #append a line break, then the word and a space
            formatted_URLs = formatted_URLs + "\n" + word + " "
            #reset counter of length to the length of a word and a space
            ACC_length = len(word) + 1
    return formatted_URLs


setup_cli_table()

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
"""    
for cve in cves:
    if (len(cve) > 0):
        print(cve[0]["_id"]) 
"""
  
for cve in cves:
    vett_URLs = []

    description = format_description(cve[0]['_source']['description']['description_data'][0]['value'], 60)

    for obj in cve[0]['_source']['references']['reference_data']:
        vett_URLs.append(obj["url"])

    URLs = format_URLs(str(vett_URLs), 10)
    #print(URLs)

    x.add_row([cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'], cve[0]["_id"], cve[0]['_source']['baseMetricV2']['impactScore'], description, URLs])
    #stampaInfo(cve[0])
    
    if (len(cve) > 0):
        cve_edbids = searchExploits(cve[0]["_id"])
        for i in cve_edbids:
            cve_all_edbids.add(i)
    pass

"""
print("All Edbids for all CVE: {0}".format(cve_all_edbids))
print()
for i in cve_all_edbids:
        os.system('searchsploit '+ str(i) + ' -w')

"""

for r in x:
    colorize(r["CVSS"], color=color_cvss(r["CVSS"]), attrs="bold") 
print(x)