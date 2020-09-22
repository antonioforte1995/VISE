#!/usr/bin/env python3

# --------------------------------------------------------
# This is the main file.
# --------------------------------------------------------


# ---------------------- IMPORTS -------------------------
from create_dashboards import *
from queries import *
from enrichment import *
from prettytable import ALL as ALL
import csv	                #to read the csv file			
import os                   #to execute the command in a subshell for "os.system(command)"
import textwrap             #to split long strings in more lines
import prettytable			#to make the cli
import colored				#to colorize the "score" field
import xlrd				    #to read xls
import re
import subprocess
from elasticsearch import Elasticsearch
import json
import time
import sys
import uuid 

# -------------------- DECLARATIONS ----------------------
cves = []
data = list()
cve_all_edbids = set()  
tempCVE = set()


es_url = "http://elastic:changeme@3.225.242.97:9200"

es = Elasticsearch(hosts=[es_url])


def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def valid(cve):
    if cve['_id'] in tempCVE:
        return False
    tempCVE.add(cve['_id'])
    return True

#to read the searching cards
workbook = xlrd.open_workbook('/home/antonio/Scrivania/VIS3/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)


# --------------------- FUNCTIONS ------------------------
   

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


#to attribute color and severity to the CVSS score, based on the reference: https://nvd.nist.gov/vuln-metrics/cvss
# 0.0       None 	 -> White
# 0.1-3.9   Low      -> Green
# 4.0-6.9   Medium 	 -> Yellow
# 7.0-8.9   High 	 -> DarkOrange
# 9.0-10.0  Critical -> Red

def color_score(score):
    score = float(score)
    severity = ""

    if score == 0.0:
        color = "white"
        severity = "NONE"
    elif (score >= 0.1) and (score <= 3.9):
        color = "green_3b"
        severity = "LOW"
    elif (score >= 4.0) and (score <= 6.9):
        color = "yellow_1"
        severity = "MEDIUM"
    elif (score >= 7.0) and (score <= 8.9):
        color = "orange_1"
        severity = "HIGH"
    elif (score >= 9.0) and (score <= 10.0):
        color = "red"
        severity = "CRITICAL"

    return color, severity



# ---------------------------- MAIN ------------------------------

#[SHOULD]control on children should be added!
def start(index_name):
    for row in range(2, worksheet.nrows):

        randomic_id = uuid.uuid1()
        
        #result of the query
        cpes = search_CPE(worksheet.cell_value(row,4), worksheet.cell_value(row,0), worksheet.cell_value(row,1), worksheet.cell_value(row,5))
        

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
                

                #for each element of the "CPEs" array, version is checked to insert the value in the right array.
                #for instance: if versionStartIncluding the value will be insert in the versionaStartIncluding array, and so on.
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


                #tempList will be used to filter the duplicates 
                tempList = None
                
                #if there is only one boundary
                if (len(versions_types) == 1):
                    tempList = search_CVE_from_single_limit(vett_cpe23Uri[i], versions_types[0], versions_types_values[0])

                #if there are two boundaries
                elif (len(versions_types) == 2):
                    tempList = search_CVE_from_interval(vett_cpe23Uri[i], versions_types, versions_types_values[0], versions_types_values[1])

                #if there is the accurate version
                else:
                    tempList = search_CVE(vett_cpe23Uri[i])

                #check on the duplicates
                tempList = [item for item in tempList if valid(item)]
                cves.append(tempList)


    #building each rows and columns of CLI and CSV
    for cve in cves:

        vett_URLs = []
        vett_remediations = []
        severity = ""
        baseScore = 0

        #add value in table, splitting in new lines the description and cpe
        if (len(cve) > 0):
            description = format_description(cve[0]['_source']['description']['description_data'][0]['value'], 60)
            cpe = format_CPE(cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'], 40)


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
                #severity = cve[0]['_source']['baseMetricV3']['cvssV3']['baseSeverity']
                baseScore = cve[0]['_source']['baseMetricV3']['cvssV3']['baseScore']
            else:
                #severity = cve[0]['_source']['baseMetricV2']['severity']
                baseScore = cve[0]['_source']['baseMetricV2']['cvssV2']['baseScore']


            #the function color_score returns 2 values, color and severity
            [color, severity] = color_score(baseScore)


            exploit_URLs = []

            #reasearching on the ExploitDB for the enrichment, each cve found is added to the "cve_all_edbids" set (in this way there are no duplicates)
            cve_edbids = searchExploits(cve[0]["_id"])
            for i in cve_edbids:
                output = subprocess.check_output('searchsploit '+ str(i) + ' -w', shell=True)

                string_output = output.decode('utf-8')
                splitted_string = string_output.split("\n")
        

                for i in range(3, len(splitted_string)-4):
                    exploit_URLs.append(escape_ansi(splitted_string[i].split('|')[-1]))
                #cve_all_edbids.add(i)

            exploit_URLs_witouth_commas = delete_commas(str(exploit_URLs))
            exploit_URLs = format_URLs(exploit_URLs_witouth_commas)


            if es.exists(index=index_name, id=cve[0]["_id"]) is False:
                result = es.create(index=index_name, id=cve[0]["_id"],body={
                    "CPE": cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
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
                result = es.update(index=index_name, id=cve[0]["_id"],body={
                    "doc": {
                        "CPE": cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
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

            HEADERS = {
            'Content-Type': 'application/json'
            }

            uri = "http://elastic:changeme@3.225.242.97:9200/.kibana/_doc/index-pattern:{0}".format(index_name)

            query = json.dumps(
                {
                    "type": "index-pattern",
                    "index-pattern": {
                        "title": index_name
                        #"timeFieldName": time.strftime("%Y%m%d-%H%M%S")
                    }
                }
            )

            r = requests.put(uri, headers=HEADERS, data=query).json()
            #print(r)

        pass
     
    vett_dashboards_links = create_dashboards(index_name)

start(sys.argv[1])