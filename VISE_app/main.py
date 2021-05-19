#!/usr/bin/env python3

# --------------------------------------------------------
# This is the main file. Used for the webapp
# --------------------------------------------------------


# ---------------------- IMPORTS -------------------------

import csv                      # to read the csv file
import os                       # to execute the command in a subshell for "os.system(command)"
import re
import subprocess
import sys
import textwrap                 # to split long strings in more lines
import time
import colored                  # to colorize the score and severity fields
import cve_searchsploit         # to search exploits related to a cveid
import prettytable              # to make the CLI
import xlrd                     # to read xls
from elasticsearch import Elasticsearch

from create_dashboards import create_dashboards
from queries import (search_CPEs, search_CVEs, search_CVEs_from_interval,
                     search_CVEs_from_single_limit)

# -------------------- DECLARATIONS ----------------------
tempCVEs = set()                 # temp set of CVEs (used to filter out duplicates in cves list)

def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


# this function checks if the cve is already in cves list
def not_duplicated(cve):
    if cve['_id'] in tempCVEs:
        return False
    tempCVEs.add(cve['_id'])
    return True



# --------------------- FUNCTIONS ------------------------

# to create and print a formatted and colorized CLI table
def cli_table(CLI_columns_headers, CLI_data, hrules=True):
    CLI_columns_headers = map(lambda x: colorize(x, attrs="bold"), CLI_columns_headers)
    
    # to create the structure (raw and column lines) of the cli table
    table = prettytable.PrettyTable(
        hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=CLI_columns_headers
    )
    for row in CLI_data:
        table.add_row(row)
    table.align = "l"
    print(table)


# to color score and severity, ref: https://pypi.org/project/colored/
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
    # accumulated line length
    ACC_length = 0
    words = description.split(" ")
    formatted_description = ""
    for word in words:
        if ACC_length + (len(word) + 1) <= max_line_length:                     # if ACC_length + len(word) and a space is <= max_line_length
            formatted_description = formatted_description + word + " "          # append the word and a space
            ACC_length = ACC_length + len(word) + 1                             # length = length + length of word + length of space
        else:
            formatted_description = formatted_description + "\n" + word + " "   # append a line break, then the word and a space
            ACC_length = len(word) + 1                                          # reset counter of length to the length of a word and a space
    return formatted_description


#to remove unwanted chars
def remove_unwanted_chars(URLs):
    URLs = URLs.replace("[", '')
    URLs = URLs.replace("'", '')
    URLs = URLs.replace("]", '')
    URLs = URLs.split(", ")
    return URLs


# the first URL (i=0) is placed in the first row, the next URLs are placed in new lines
def format_URLs(URLs):
    formatted_URLs = URLs[0]
    i = 0
    for URL in URLs:
        # without this "if" there is an empty line before the URLs
        if i == 0:
            i = i+1
        else:
            formatted_URLs = formatted_URLs + "\n" + URL + " "
    return formatted_URLs


# to split the string based on "max_line_lenght"
def format_CPE(CPE, max_line_length):
    formatted_CPE = "\n".join(textwrap.wrap(CPE, max_line_length))
    return formatted_CPE


# to attribute color and severity to the CVSS score, based on the reference: https://nvd.nist.gov/vuln-metrics/cvss and https://nvd.nist.gov/general/nvd-dashboard
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


def create_csv(name, CSV_data):
    fld = "static/assets/CSVs/"
    if not os.path.exists('static/assets/CSVs/'):
        os.makedirs('static/assets/CSVs/')
    fname = fld+name+'_output.csv'
    os.system("touch {0}".format(fname))
    with open(fname, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(CSV_data)
        return fname


# this function returns exploit ids for a specific cve_id
def searchExploits(cve_id):  
    #cve_searchsploit.update_db()
    edbids=[]
    edbids = cve_searchsploit.edbid_from_cve(cve_id)
    return edbids


# this function removes the gap between xlsx data and form data
def convert_worksheet_row_to_dictionary(worksheet, package):
    package_dict = {}
    package_dict['Product Name'] = worksheet.cell_value(package,0)
    package_dict['Version Number'] = worksheet.cell_value(package,1)
    package_dict['Vendor Name'] = worksheet.cell_value(package,2)
    package_dict['Target Software'] = worksheet.cell_value(package,3)
    package_dict['Product Type'] = worksheet.cell_value(package,4)
    return package_dict


# this function returns a list of cpes and the searched_cpe23Uri matching the input package
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


# this function builds the cpe23Uri with a specific version to search the related CVEs
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
    
    CLI_data = []
    CSV_data = []
    # clear global set tempCVEs to not have problems in the new search
    tempCVEs.clear()

    # columns headers in CLI
    CLI_columns_headers = ["CPE", "CVE-ID", "CVSSv3 BASE SCORE", "SEVERITY", "DESCRIPTION", "URLs"]

    # columns headers in CSV
    CSV_data.append(["CPE", "CVE-ID", "CVSSv3 BASE SCORE", "SEVERITY", "DESCRIPTION", "URLs", "REMEDIATIONS", "CWE-ID", "EXPLOITS" ])


    # define Elasticsearch host
    es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@localhost:9200"
    es = Elasticsearch(hosts=[es_url])


    #Conditional definition to use both xlsx and form data
    if usingXLS and type(worksheet) is str:
        workbook = xlrd.open_workbook(worksheet, on_demand = True)
        worksheet = workbook.sheet_by_index(0)
    else:
        pass
    
    #if we are not using the searching card (usingXLS is false) then we start from the beginning, otherwise we exclude the first row
    packages = range(1, worksheet.nrows) if usingXLS else range(len(worksheet))

    for package in packages:
        cpes = []
        cves = []               
        searched_cpe23Uri = ""
        CVEs_tempList = []  #CVEs_tempList is used to filter out CVE duplicates


        if usingXLS:
            package = convert_worksheet_row_to_dictionary(worksheet, package)
            searched_cpe23Uri, cpes = searchCPEs(package)
        else:
            searched_cpe23Uri, cpes = searchCPEs(worksheet[package])
            
        # if no CPE is returned, jump to new package (new iteration)
        if (len(cpes) == 0):
            continue

        # for all retrieved CPEs ..
        for i in range(0, len(cpes)):
            version_types_list = ['versionStartIncluding', 'versionStartExcluding', 'versionEndIncluding', 'versionEndExcluding']
            cpe23Uri_to_submit = {}
            cpe23Uri_to_submit['cpe23Uri'] = cpes[i]["_source"]["cpe23Uri"]
            cpe23Uri_to_submit['version_types'] = []    # array that has the type of version range (ve.g. ersionStartIncluding, versionStartExcluding, ...)
            cpe23Uri_to_submit['version_types_values'] = [] # array that has the effective values of the range (e.g. value of versionStartIncluding, ...)


            # for each version type we check its presence in the current CPE
            # if it is present we add version type and version type value to cpe23Uri_to_submit dictionary
            for version_type in version_types_list:
                if version_type in cpes[i]["_source"]:
                    cpe23Uri_to_submit['version_types'].append(version_type) 
                    cpe23Uri_to_submit['version_types_values'].append(cpes[i]["_source"][version_type])
            
            # if only one version type (one boundary)..
            if (len(cpe23Uri_to_submit['version_types']) == 1):
                CVEs_tempList = search_CVEs_from_single_limit(cpe23Uri_to_submit)
                CVEs_tempList += search_CVEs_from_single_limit(cpe23Uri_to_submit, ".children")

            # if two version types (two boundary)..
            elif (len(cpe23Uri_to_submit['version_types']) == 2):
                CVEs_tempList = search_CVEs_from_interval(cpe23Uri_to_submit)
                CVEs_tempList += search_CVEs_from_interval(cpe23Uri_to_submit, ".children")

            # if no version type (no boundary) search CVEs for cpe23Uri with specific version
            else:
                cpe23Uri = build_cpe23Uri_with_specific_version(cpe23Uri_to_submit['cpe23Uri'], searched_cpe23Uri)
                CVEs_tempList = search_CVEs(cpe23Uri)

            # check on duplicates
            if(len(CVEs_tempList)>0):
                CVEs_tempList = [cve for cve in CVEs_tempList if not_duplicated(cve)]

                for cve in CVEs_tempList:
                    cve['searched_cpe23Uri'] = searched_cpe23Uri
                    # build cves list
                    cves.append([cve])

            
        for cve in cves:
            severity = ""
            baseScore = 0
            URLs_types = ['CLI_URLs', 'CSV_URLs', 'remediations', 'exploit_URLs']
            URLs = {}
            # build URLs dictionary with (CLI_URLs', 'CSV_URLs', 'remediations', 'exploit_URLs') fields
            for URLs_type in URLs_types:
                URLs[URLs_type] = []
            

            # split in new lines the description and searched_cpe23Uri
            if (len(cve) > 0):
                description = format_description(cve[0]['_source']['description']['description_data'][0]['value'], 60)
                searched_cpe23Uri = format_CPE(cve[0]['searched_cpe23Uri'], 40)


                # the "Vendor Advisory URL" will be placed in the "CLI_URLs" field and in the "remediations" one
                # others URLs will be placed in the "CLI_URLs" field and in the "CSV_URLs" one
                for obj in cve[0]['_source']['references']['reference_data']:
                    if("Vendor Advisory" in obj["tags"]):
                        URLs['remediations'].append(obj["url"])
                    else:
                        URLs['CSV_URLs'].append(obj["url"])
                    URLs['CLI_URLs'].append(obj["url"])

                
                # retrieve exploit ids for specific cve_id
                cve_edbids = searchExploits(cve[0]["_id"])
                # for each exploit id we retrieve related exploit URL
                for i in cve_edbids:
                    try:
                        output = subprocess.check_output('searchsploit '+ str(i) + ' -w ', shell=True, stderr=DEVNULL)

                        string_output = output.decode('utf-8')
                        splitted_string = string_output.split("\n")

                        for i in range(3, len(splitted_string)-4):
                            # add exploit current URL to 'exploit_URLs' and 'CLI_URLs' fields
                            URLs['exploit_URLs'].append(escape_ansi(splitted_string[i].split('|')[-1][1:]))
                            URLs['CLI_URLs'].append(escape_ansi(splitted_string[i].split('|')[-1][1:]))
                    except Exception as e:
                        print(e)


                # remove unwanted chars from URLs and format them to better display
                for URLs_type in URLs_types:
                    URLs[URLs_type]= format_URLs(remove_unwanted_chars(str(URLs[URLs_type])))


                # if CVSSv3 baseScore not present use CVSSv2 baseScore
                if ("baseMetricV3" in cve[0]['_source']):
                    baseScore = cve[0]['_source']['baseMetricV3']['cvssV3']['baseScore']
                else:
                    baseScore = cve[0]['_source']['baseMetricV2']['cvssV2']['baseScore']


                # given a baseScore this function returns 2 values, color and qualitative severity
                [color, severity] = color_score(baseScore)

                # add CLI_data in the CLI
                CLI_data.append(
                    [
                        colorize(searched_cpe23Uri),
                        colorize(cve[0]["_id"]),
                        colorize(baseScore, color, attrs="bold"),
                        colorize(severity, color, attrs="bold"),
                        colorize(description),
                        colorize(URLs['CLI_URLs'])
                    ]
                )

                # add CSV_data in the CSV
                CSV_data.append(
                    [   
                        cve[0]['searched_cpe23Uri'],
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

                # create or update index for current search on elasticsearch
                if es.exists(index=index_name, id=cve[0]["_id"]) is False:
                    es.create(index=index_name, id=cve[0]["_id"],body={
                        "CPE": cve[0]['searched_cpe23Uri'],
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
                            "CPE": cve[0]['searched_cpe23Uri'],#cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                            "CVE": cve[0]["_id"],
                            "SCORE": baseScore,
                            "SEVERITY": severity,
                            "DESCRIPTION": description,
                            "REMEDIATIONS": URLs['remediations'],
                            "CWE": cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value'],
                            "EXPLOIT": URLs['exploit_URLs']
                        }, "doc_as_upsert": True   
                    })
                        
    # create a CSV report for current search
    csvName = create_csv(index_name, CSV_data)
    # create dashboards for current search and return links to them
    report_links = create_dashboards(index_name)
    # add CSV path to report_links list
    report_links.append(csvName)

    # if VISE is executed from CLI, print report table in CLI
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