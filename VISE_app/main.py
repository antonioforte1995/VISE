#!/usr/bin/env python3

# --------------------------------------------------------
# This is the main file. Used for the webapp
# --------------------------------------------------------


# ---------------------- IMPORTS -------------------------

import csv  # to read the csv file
import json
import os  # to execute the command in a subshell for "os.system(command)"
import re
import subprocess
import sys
import textwrap  # to split long strings in more lines
import time
import uuid
from pprint import pprint

import colored  # to colorize the "score" field
import cve_searchsploit
import prettytable  # to make the cli
import xlrd  # to read xls
from elasticsearch import Elasticsearch
from prettytable import ALL as ALL

from create_dashboards import create_dashboards, requests
from queries import (search_CPE, search_CVE, search_CVE_from_interval,
                     search_CVE_from_single_limit)

# -------------------- DECLARATIONS ----------------------
tempCVE = set()
IS_DEBUG = True

def dprint(a):
    global IS_DEBUG
    if IS_DEBUG:
        print(a)

def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def valid(cve):
    if cve['_id'] in tempCVE:
        return False
    tempCVE.add(cve['_id'])
    return True



# --------------------- FUNCTIONS ------------------------

# to create and print a formatted and colorized cli table
def cli_table(columns, data, hrules=True):
    columns = map(lambda x: colorize(x, attrs="bold"), columns)
    
    #to create the structure (raw and column lines) of the cli table
    table = prettytable.PrettyTable(
        hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=columns
    )
    for row in data:
        table.add_row(row)
    table.align = "l"
    print(table)


#to color the score, ref: https://pypi.org/project/colored/
def colorize(string, color=None, highlight=None, attrs=None):
    """Apply style on a string"""
    return colored.stylize(
        string,
        (colored.fg(color) if color else "")
        + (colored.bg(highlight) if highlight else "")
        + (colored.attr(attrs) if attrs else ""),
    )

# to split the description based on "max_line_lenght"
def format_description(description, max_line_length):
    #accumulated line length
    ACC_length = 0
    words = description.split(" ")
    formatted_description = ""
    for word in words:
        if ACC_length + (len(word) + 1) <= max_line_length:                     #if ACC_length + len(word) and a space is <= max_line_length
            formatted_description = formatted_description + word + " "          #append the word and a space
            ACC_length = ACC_length + len(word) + 1                             #length = length + length of word + length of space
        else:
            formatted_description = formatted_description + "\n" + word + " "   #append a line break, then the word and a space
            ACC_length = len(word) + 1                                          #reset counter of length to the length of a word and a space
    return formatted_description


#the first URL (i=0) is placed in the first row, the next URLs are placed in new lines
#without this "if" there is an empty line before the URLs
def format_URLs(URLs):
    formatted_URLs = URLs[0]
    i = 0
    for URL in URLs:
        if i == 0:
            i = i+1
        else:
            formatted_URLs = formatted_URLs + "\n" + URL + " "
    return formatted_URLs


#to remove special chars
def delete_commas(URLs):
    URLs = URLs.replace("[", '')
    URLs = URLs.replace("'", '')
    URLs = URLs.replace("]", '')
    URLs = URLs.split(", ")
    return URLs


#to split the string based on "max_line_lenght"
def format_CPE(CPE, max_line_length):
    formatted_CPE = "\n".join(textwrap.wrap(CPE, max_line_length))
    return formatted_CPE


#to attribute color and severity to the CVSS score, based on the reference: https://nvd.nist.gov/vuln-metrics/cvss and https://nvd.nist.gov/general/nvd-dashboard
# 0.0       None 	 -> White
# 0.1-3.9   Low      -> Yellow
# 4.0-6.9   Medium 	 -> Orange
# 7.0-8.9   High 	 -> Red
# 9.0-10.0  Critical -> DarkRed

def color_score(score):
    score = float(score)
    severity = ""

    if score == 0.0:
        color = "white"
        severity = "NONE"
    elif (score >= 0.1) and (score <= 3.9):
        color = "yellow_1"
        severity = "LOW"
    elif (score >= 4.0) and (score <= 6.9):
        color = "orange_1"
        severity = "MEDIUM"
    elif (score >= 7.0) and (score <= 8.9):
        color = "red"
        severity = "HIGH"
    elif (score >= 9.0) and (score <= 10.0):
        color = "dark_red_2"
        severity = "CRITICAL"

    return color, severity

def create_csv(name, row_data):
    fld = "CSVs/"
    fname = fld+name+'_output.csv'
    os.system("touch {0}".format(fname))
    print(fname)
    with open(fname, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(row_data)
        return fname
    

def searchExploits(cve_id):
    
    #cve_searchsploit.update_db()
    cve_exploits = set()
    edbids=[]
    edbids = cve_searchsploit.edbid_from_cve(cve_id)
    for i in edbids:
        cve_exploits.add(i)
    
    return edbids


# ---------------------------- MAIN ------------------------------

def start(index_name, worksheet = None, usingXLS = True, gui=True):
    try:
        from subprocess import DEVNULL  # Python 3.
    except ImportError:
        DEVNULL = open(os.devnull, 'wb')


    #Initial variables, moved from the outside so as not to give problems in the import
    cves = []
    data = list()
    columns = ["CPE", "CVE-ID", "CVSSv3 BASE SCORE", "SEVERITY", "DESCRIPTION", "URLs"]
    global IS_DEBUG
    IS_DEBUG = gui
    
    es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@localhost:9200"

    es = Elasticsearch(hosts=[es_url])
    tempCVE.clear()
    csv_data = list()

    #fields used in CSV
    csv_data.append(
        [   
            "CPE",
            "CVE-ID",
            "CVSSv3 BASE SCORE",
            "SEVERITY",
            "DESCRIPTION",
            "URLs",
            "REMEDIATIONS",
            "CWE-ID",
            "EXPLOITS" 
        ]
    )

    #Conditional range definition to use both xls and lists
    if usingXLS and type(worksheet) is str:
        workbook = xlrd.open_workbook(worksheet, on_demand = True)
        worksheet = workbook.sheet_by_index(0)
    elif usingXLS:
        pass
    else:
        dprint(len(worksheet))
    
    #if we are not using the searching card (usingXLS is false) then we start from the beginning, otherwise we exclude the first 2 rows
    rowRange = range(1, worksheet.nrows) if usingXLS else range(len(worksheet))
    for row in rowRange:

        #result of the query
        #Also in this case we condition the generation of the array so as to make its use dynamic
        cpes = []
        cves = []
        searched_CPE = ""

        if usingXLS:
            vendor = worksheet.cell_value(row,4)
            target_software = worksheet.cell_value(row,5)
            cpetype = worksheet.cell_value(row,2)
            if cpetype == "Application":
                cpetype = "a"
            elif cpetype == "OS":
                cpetype = "o"
            elif cpetype == "Hardware":
                cpetype = "h"
            else:
                cpetype = "a"

            if len(vendor) < 1:
                vendor = ".*"
            if (target_software == ""):
                target_software = ".*"
            cpes = search_CPE(vendor, worksheet.cell_value(row,0), worksheet.cell_value(row,1), target_software, cpetype)
            if vendor == ".*":
                vendor = "*"
            if (target_software == ".*"):
                target_software = "*"
            searched_CPE = "cpe:2.3:{4}:{0}:{1}:{2}:*:*:*:*:{3}:*:*".format(vendor, worksheet.cell_value(row,0), worksheet.cell_value(row,1), target_software, cpetype)
        else:
            vendor = worksheet[row]['VendorInput']
            target_software = worksheet[row]['SoftwareInput']
            cpetype = worksheet[row]['ProductInput']
            if cpetype == "Application":
                cpetype = "a"
            elif cpetype == "OS":
                cpetype = "o"
            elif cpetype == "Hardware":
                cpetype = "h"
            else:
                cpetype = "a"

            if len(vendor) < 1:
                vendor = ".*"
            if (target_software == ""):
                target_software = ".*"
            
            cpes = search_CPE(vendor, worksheet[row]['PackageInput'], worksheet[row]['VersionInput'], target_software, cpetype)
            if vendor == ".*":
                vendor = "*"
            if (target_software == ".*"):
                target_software = "*"
            searched_CPE = "cpe:2.3:{4}:{0}:{1}:{2}:*:*:*:*:{3}:*:*".format(vendor, worksheet[row]['PackageInput'], worksheet[row]['VersionInput'], target_software, cpetype)
            

        #four arrays are declared, they will contain information about the type and the number of version
        vett_cpe23Uri = [0]*len(cpes)
        vett_versionStartIncluding = [0]*len(cpes)
        vett_versionStartExcluding = [0]*len(cpes)
        vett_versionEndIncluding = [0]*len(cpes)
        vett_versionEndExcluding = [0]*len(cpes)

 
        #for all the CPEs that have a range or a wildcard, it should be found the start and the end of this range
        if (len(cpes) > 0):
            for i in range(0, len(cpes)):
                not_null_version_types = 0          #if the CPE exists there will be the version too, so the counter is initialized to 0
                versions_types = []                 #array that has the type of the range (if StartIncluding, StartExcluding, ...)
                versions_types_values = []          #array that has the effective values of the range (value of StartIncluding, ...)

                #result of the query
                vett_cpe23Uri[i] = cpes[i]["_source"]["cpe23Uri"]

                #for each object in the "CPEs" array, version is checked to insert the value in the right array.
                #for instance: if versionStartIncluding the value will be insert in the versionStartIncluding array, and so on.
                #Same for all 4 "if"
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

                
                #tempList and tempList1 will be used to filter the duplicates 
                tempList = []
                tempList1 = []
                
                #if there is only one boundary
                if (len(versions_types) == 1):
                    tempList = search_CVE_from_single_limit(vett_cpe23Uri[i], versions_types[0], versions_types_values[0])
                    tempList1 = search_CVE_from_single_limit(vett_cpe23Uri[i], versions_types[0], versions_types_values[0], ".children")

                #if there are two boundaries
                elif (len(versions_types) == 2):
                    tempList = search_CVE_from_interval(vett_cpe23Uri[i], versions_types, versions_types_values[0], versions_types_values[1])
                    tempList1 = search_CVE_from_interval(vett_cpe23Uri[i], versions_types, versions_types_values[0], versions_types_values[1], ".children")

                #if there is the accurate version
                else:
                    temp_cpe = vett_cpe23Uri[i].split(':')
                    temp_searched_CPE = searched_CPE.split(':')
                    temp_cpe[5] = temp_searched_CPE[5]
                    vett_cpe23Uri[i] = ':'.join(temp_cpe)
                    tempList = search_CVE(vett_cpe23Uri[i])

                #check on duplicates
                tempList = [item for item in tempList if valid(item)]
                for tmp in tempList:
                    tmp['searchedCPE'] = searched_CPE
                
                if len(tempList) == 1:
                    cves.append(tempList)
                elif len(tempList) > 1:
                    for t in tempList:
                        cves.append([t])
                else:
                    pass


                if(len(tempList1)>0):
                    tempList1 = [item for item in tempList1 if valid(item)]

                    for tmp in tempList1:
                        tmp['searchedCPE'] = searched_CPE

                    if len(tempList1) == 1:
                        cves.append(tempList1)
                    elif len(tempList1) > 1:
                        for t in tempList1:
                            cves.append([t])
                    else:
                        pass

                
            #building each rows and columns of CLI and CSV
            for cve in cves:

                vett_URLs = []
                vett_remediations = []
                severity = ""
                baseScore = 0

                #add value in table, splitting in new lines the description and cpe
                if (len(cve) > 0):
                    description = format_description(cve[0]['_source']['description']['description_data'][0]['value'], 60)
                    cpe = format_CPE(cve[0]['searchedCPE'], 40) #cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'], 40)


                    #enrichment, the "Vendor Advisory URL" will be placed in the "URL" field (CLI) and in the "Remediation" one (CSV)
                    #[SHOULD] actually we should control more than the "VendorAdvisory" tag and return a better result
                    for obj in cve[0]['_source']['references']['reference_data']:
                        if("Vendor Advisory" in obj["tags"]):
                            vett_remediations.append(obj["url"])
                        vett_URLs.append(obj["url"])


                    #delete commas to deal with URLs in CLI and (first of all) in CSV 
                    URLs_witouth_commas = delete_commas(str(vett_URLs))
                    remediations_witouth_commas = delete_commas(str(vett_remediations))
                    URLs = format_URLs(URLs_witouth_commas)
                    remediations = format_URLs(remediations_witouth_commas)


                    #"impactScore" is a subpart of "baseScore", this last one is reported by NIST. 
                    if ("baseMetricV3" in cve[0]['_source']):
                        baseScore = cve[0]['_source']['baseMetricV3']['cvssV3']['baseScore']
                    else:
                        baseScore = cve[0]['_source']['baseMetricV2']['cvssV2']['baseScore']


                    #the function color_score returns 2 values, color and severity
                    [color, severity] = color_score(baseScore)

                    #add data in the CLI
                    data.append(
                        [
                            colorize(cpe),
                            colorize(cve[0]["_id"]),
                            colorize(baseScore, color, attrs="bold"),
                            colorize(severity, color, attrs="bold"),
                            colorize(description),
                            colorize(URLs)
                        ]
                    )

                    exploit_URLs = []
                    #reasearching on the ExploitDB for the enrichment
                    cve_edbids = searchExploits(cve[0]["_id"])
                    for i in cve_edbids:
                        try:
                            output = subprocess.check_output('searchsploit '+ str(i) + ' -w ', shell=True, stderr=DEVNULL)

                            string_output = output.decode('utf-8')
                            splitted_string = string_output.split("\n")

                            for i in range(3, len(splitted_string)-4):
                                exploit_URLs.append(escape_ansi(splitted_string[i].split('|')[-1]))
                        except Exception as e:
                            dprint(e)

                    exploit_URLs_witouth_commas = delete_commas(str(exploit_URLs))
                    exploit_URLs = format_URLs(exploit_URLs_witouth_commas)

                    csv_data.append(
                        [   
                            cve[0]['searchedCPE'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                            cve[0]["_id"],
                            baseScore,
                            severity,
                            description,
                            URLs,
                            remediations,
                            cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                            exploit_URLs
                        ]
                    )


                    if es.exists(index=index_name, id=cve[0]["_id"]) is False:
                        es.create(index=index_name, id=cve[0]["_id"],body={
                            "CPE": cve[0]['searchedCPE'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                            "CVE": cve[0]["_id"],
                            "SCORE": baseScore,
                            "SEVERITY": severity,
                            "DESCRIPTION": description,
                            "URLs": URLs,
                            "REMEDIATIONS": remediations,
                            "CWE": cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                            "EXPLOIT": exploit_URLs
                        })
                    else:  
                        es.update(index=index_name, id=cve[0]["_id"],body={
                            "doc": {
                                "CPE": cve[0]['searchedCPE'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                                "CVE": cve[0]["_id"],
                                "SCORE": baseScore,
                                "SEVERITY": severity,
                                "DESCRIPTION": description,
                                "URLs": URLs,
                                "REMEDIATIONS": remediations,
                                "CWE": cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                                "EXPLOIT": exploit_URLs
                            }, "doc_as_upsert": True   
                        })
                        

    csvName = create_csv(index_name, csv_data)
    vett_dashboards_links = create_dashboards(index_name)
    vett_dashboards_links.append(csvName)
    if not gui:
        cli_table(columns, data, hrules=True)

    return vett_dashboards_links



if __name__ == "__main__":
    #to read the searching cards
    workbook = xlrd.open_workbook(sys.argv[1], on_demand = True)
    worksheet = workbook.sheet_by_index(0)
    idx = str(int(time.time()))
    res = start(idx, worksheet, True, gui=False)
    print("\nCHECK RESULTS AT FOLLOWING URLs:")
    print("         {0}\n".format(res))