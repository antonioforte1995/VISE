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

from create_dashboards import create_dashboards, requests
from queries import (search_CPEs, search_CVE, search_CVE_from_interval,
                     search_CVE_from_single_limit)

# -------------------- DECLARATIONS ----------------------
tempCVE = set()

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
def cli_table(CLI_columns_headers, CLI_data, hrules=True):
    CLI_columns_headers = map(lambda x: colorize(x, attrs="bold"), CLI_columns_headers)
    
    #to create the structure (raw and column lines) of the cli table
    table = prettytable.PrettyTable(
        hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=CLI_columns_headers
    )
    for package in CLI_data:
        table.add_row(package)
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
    fld = "static/assets/CSVs/"
    if not os.path.exists('static/assets/CSVs/'):
        os.makedirs('static/assets/CSVs/')
    fname = fld+name+'_output.csv'
    os.system("touch {0}".format(fname))
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


def convert_worksheet_row_to_dictionary(worksheet, package):
    package_dict = {}
    package_dict['Product Name'] = worksheet.cell_value(package,0)
    package_dict['Version Number'] = worksheet.cell_value(package,1)
    package_dict['Vendor Name'] = worksheet.cell_value(package,2)
    package_dict['Target Software'] = worksheet.cell_value(package,3)
    package_dict['Product Type'] = worksheet.cell_value(package,4)

    return package_dict


def searchCPEs(package):

    if package['Product Type'] in ["Application", "application", "a", "A"]:
        package['Product Type'] = "a"
    elif package['Product Type'] in ["OS", "os", "O", "o"]:
        package['Product Type'] = "o"
    elif package['Product Type'] in ["Hardware", "hardware", "h", "H"]:
        package['Product Type'] = "h"
    else:
        package['Product Type'] = "a"

    if (package['Vendor Name'] == ""):
        package['Vendor Name'] = ".*"

    if (package['Target Software'] == ""):
        package['Target Software'] = ".*"

    searched_cpe23Uri = "cpe:2.3:{0}:{1}:{2}:{3}:.*:.*:.*:.*:{4}:.*:.*".format(package['Product Type'], package['Vendor Name'], package['Product Name'], package['Version Number'], package['Target Software'])
    cpes = search_CPEs(searched_cpe23Uri)

    searched_cpe23Uri = searched_cpe23Uri.replace(".*", "*")

    return searched_cpe23Uri, cpes


def build_cpe23Uri_with_specific_version(cpe23Uri, searched_cpe23Uri):
    temp_cpe23Uri = cpe23Uri.split(':')
    temp_searched_cpe23Uri = searched_cpe23Uri.split(':')
    temp_cpe23Uri[5] = temp_searched_cpe23Uri[5]
    cpe23Uri = ':'.join(temp_cpe23Uri)
    return cpe23Uri

# ---------------------------- MAIN ------------------------------

def start(index_name, worksheet = None, usingXLS = True, gui=True):
    
    try:
        from subprocess import DEVNULL  # Python 3.
    except ImportError:
        DEVNULL = open(os.devnull, 'wb')
    

    #Initial variables, moved from the outside so as not to give problems in the import
    CLI_data = list()
    CSV_data = list()
    tempCVE.clear()

    # columns headers in CLI
    CLI_columns_headers = ["CPE", "CVE-ID", "CVSSv3 BASE SCORE", "SEVERITY", "DESCRIPTION", "URLs"]

    # columns headers in CSV
    CSV_data.append(["CPE", "CVE-ID", "CVSSv3 BASE SCORE", "SEVERITY", "DESCRIPTION", "URLs", "REMEDIATIONS", "CWE-ID", "EXPLOITS" ])


    # define Elasticsearch host
    es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@localhost:9200"
    es = Elasticsearch(hosts=[es_url])


    #Conditional definition to use both xlsx and lists
    if usingXLS and type(worksheet) is str:
        workbook = xlrd.open_workbook(worksheet, on_demand = True)
        worksheet = workbook.sheet_by_index(0)
    else:
        pass
    
    #if we are not using the searching card (usingXLS is false) then we start from the beginning, otherwise we exclude the first 2 rows
    packages = range(1, worksheet.nrows) if usingXLS else range(len(worksheet))

    for package in packages:
        cpes = []
        #CVEs_tempList1 and CVEs_tempList2 will be used to filter the duplicates
        CVEs_tempList = list()
        cves = []
        searched_cpe23Uri = ""

        if usingXLS:
            package = convert_worksheet_row_to_dictionary(worksheet, package)
            searched_cpe23Uri, cpes = searchCPEs(package)
        else:
            searched_cpe23Uri, cpes = searchCPEs(worksheet[package])
            
 
        #for all the CPEs that have a range or a wildcard, it should be found the start and the end of this range
        if (len(cpes) == 0):
            continue

        for i in range(0, len(cpes)):
            version_types_list = ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding']
            cpe23Uri_to_submit = {}
            cpe23Uri_to_submit['cpe23Uri'] = cpes[i]["_source"]["cpe23Uri"]
            cpe23Uri_to_submit['version_types'] = []    #array that has the type of version range (versionStartIncluding, versionStartExcluding, ...)
            cpe23Uri_to_submit['version_types_values'] = [] #array that has the effective values of the range (value of versionStartIncluding, ...)

            #for each object in the "CPEs" array, version is checked to insert the value in the right array.
            #for instance: if versionStartIncluding the value will be insert in the versionStartIncluding array, and so on.
            #Same for all 4 "if"

            for version_type in version_types_list:
                if version_type in cpes[i]["_source"]:
                    cpe23Uri_to_submit['version_types'].append(version_type) 
                    cpe23Uri_to_submit['version_types_values'].append(cpes[i]["_source"][version_type])
            
            #if there is only one boundary
            if (len(cpe23Uri_to_submit['version_types']) == 1):
                CVEs_tempList = search_CVE_from_single_limit(cpe23Uri_to_submit)
                CVEs_tempList += search_CVE_from_single_limit(cpe23Uri_to_submit, ".children")

            #if there are two boundaries
            elif (len(cpe23Uri_to_submit['version_types']) == 2):
                CVEs_tempList = search_CVE_from_interval(cpe23Uri_to_submit)
                CVEs_tempList += search_CVE_from_interval(cpe23Uri_to_submit, ".children")

            #if there is the accurate version
            else:
                cpe23Uri = build_cpe23Uri_with_specific_version(cpe23Uri_to_submit['cpe23Uri'], searched_cpe23Uri)
                CVEs_tempList = search_CVE(cpe23Uri)

            #check on duplicates
            if(len(CVEs_tempList)>0):
                CVEs_tempList = [item for item in CVEs_tempList if valid(item)]

                for tmp in CVEs_tempList:
                    tmp['searchedCPE'] = searched_cpe23Uri
                    cves.append([tmp])

            
        #building each rows and columns of CLI and CSV
        for cve in cves:
            URLs_types = ['CLI_URLs', 'CSV_URLs', 'remediations', 'exploit_URLs']
            URLs = {}
            for URLs_type in URLs_types:
                URLs[URLs_type] = []

            severity = ""
            baseScore = 0

            #add value in table, splitting in new lines the description and cpe
            if (len(cve) > 0):
                description = format_description(cve[0]['_source']['description']['description_data'][0]['value'], 60)
                cpe = format_CPE(cve[0]['searchedCPE'], 40)


                #enrichment, the "Vendor Advisory URL" will be placed in the "URL" field (CLI) and in the "Remediation" one (CSV)
                #[SHOULD] actually we should control more than the "VendorAdvisory" tag and return a better result
                for obj in cve[0]['_source']['references']['reference_data']:
                    if("Vendor Advisory" in obj["tags"]):
                        URLs['remediations'].append(obj["url"])
                    else:
                        URLs['CSV_URLs'].append(obj["url"])
                    URLs['CLI_URLs'].append(obj["url"])

                
                #reasearching on the ExploitDB for the enrichment
                cve_edbids = searchExploits(cve[0]["_id"])
                for i in cve_edbids:
                    try:
                        output = subprocess.check_output('searchsploit '+ str(i) + ' -w ', shell=True, stderr=DEVNULL)

                        string_output = output.decode('utf-8')
                        splitted_string = string_output.split("\n")

                        for i in range(3, len(splitted_string)-4):
                            URLs['exploit_URLs'].append(escape_ansi(splitted_string[i].split('|')[-1][1:]))
                            URLs['CLI_URLs'].append(escape_ansi(splitted_string[i].split('|')[-1][1:]))
                    except Exception as e:
                        print(e)


                #delete commas to deal with URLs in CLI and (first of all) in CSV 
                for URLs_type in URLs_types:
                    URLs[URLs_type]= format_URLs(delete_commas(str(URLs[URLs_type])))


                #"impactScore" is a subpart of "baseScore", this last one is reported by NIST. 
                if ("baseMetricV3" in cve[0]['_source']):
                    baseScore = cve[0]['_source']['baseMetricV3']['cvssV3']['baseScore']
                else:
                    baseScore = cve[0]['_source']['baseMetricV2']['cvssV2']['baseScore']


                #the function color_score returns 2 values, color and severity
                [color, severity] = color_score(baseScore)

                #add CLI_data in the CLI
                CLI_data.append(
                    [
                        colorize(cpe),
                        colorize(cve[0]["_id"]),
                        colorize(baseScore, color, attrs="bold"),
                        colorize(severity, color, attrs="bold"),
                        colorize(description),
                        colorize(URLs['CLI_URLs'])
                    ]
                )

                

                CSV_data.append(
                    [   
                        cve[0]['searchedCPE'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                        cve[0]["_id"],
                        baseScore,
                        severity,
                        description,
                        URLs['CSV_URLs'],
                        URLs['remediations'],
                        cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                        URLs['exploit_URLs']
                    ]
                )


                if es.exists(index=index_name, id=cve[0]["_id"]) is False:
                    es.create(index=index_name, id=cve[0]["_id"],body={
                        "CPE": cve[0]['searchedCPE'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                        "CVE": cve[0]["_id"],
                        "SCORE": baseScore,
                        "SEVERITY": severity,
                        "DESCRIPTION": description,
                        "REMEDIATIONS": URLs['remediations'],
                        "CWE": cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                        "EXPLOIT": URLs['exploit_URLs']
                    })
                else:  
                    es.update(index=index_name, id=cve[0]["_id"],body={
                        "doc": {
                            "CPE": cve[0]['searchedCPE'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                            "CVE": cve[0]["_id"],
                            "SCORE": baseScore,
                            "SEVERITY": severity,
                            "DESCRIPTION": description,
                            "REMEDIATIONS": URLs['remediations'],
                            "CWE": cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                            "EXPLOIT": URLs['exploit_URLs']
                        }, "doc_as_upsert": True   
                    })
                        

    csvName = create_csv(index_name, CSV_data)
    report_links = create_dashboards(index_name)
    report_links.append(csvName)
    if not gui:
        cli_table(CLI_columns_headers, CLI_data, hrules=True)

    return report_links



if __name__ == "__main__":
    #to read the searching card
    if(len(sys.argv)<2):
        print("PLEASE GIVE THE SEARCHING CARD !! \n")
        print("A correct example of use is:\n   ./main static/assets/SearchingCards/SearchingCard.xlsx\n")
    else:
        workbook = xlrd.open_workbook(sys.argv[1], on_demand = True)
        worksheet = workbook.sheet_by_index(0)
        index = str(int(time.time()))
        res = start(index, worksheet, True, gui=False)
        print("\nCHECK RESULTS AT FOLLOWING URLs:")
        print("         {0}\n".format(res))