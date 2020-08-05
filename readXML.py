#!/usr/bin/env python3
import xlrd
from queries import *
from enrichment import *
import os
import colored
import prettytable
from prettytable import ALL as ALL
import textwrap
import csv

  

workbook = xlrd.open_workbook('/home/antonio/Scrivania/VIS3/SearchingCard.xlsx', on_demand = True)
#workbook = xlrd.open_workbook('/home/giampaolo/Desktop/VIS3/VIS3/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)

cves = []
data = list()
csv_data = list()
cve_all_edbids = set()


columns = ["CPE", "CVE", "SCORE", "SEVERITY", "DESCRIPTION", "URLs"]

def cli_table(columns, data, hrules=True):
    """Print a table"""
    columns = map(lambda x: colorize(x, attrs="bold"), columns)
    table = prettytable.PrettyTable(
        hrules=prettytable.ALL if hrules else prettytable.FRAME, field_names=columns
    )
    for row in data:
        table.add_row(row)
    table.align = "l"
    print(table)
   


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


def format_URLs(URLs):
    formatted_URLs = URLs[0]
    i = 0
    for URL in URLs:
        if i == 0:
            i = i+1
        else:
            formatted_URLs = formatted_URLs + "\n" + URL + " "
    return formatted_URLs


def delete_commas(URLs):
    #accumulated line length
    URLs = URLs.replace("[", '')
    URLs = URLs.replace("'", '')
    URLs = URLs.replace("]", '')
    ACC_length = 0
    URLs = URLs.split(", ")
    return URLs


def format_URL(URLs, max_line_length):
    formatted_URLs = URLs[0]
    i = 0
    for URL in URLs:
        if i == 0:
            i = i+1
        else:   
            formatted_URL = "\n".join(textwrap.wrap(URL, max_line_length))
            formatted_URLs = formatted_URLs + "\n" + formatted_URL + " "

    return formatted_URLs


def format_CPE(CPE, max_line_length):
    formatted_CPE = "\n".join(textwrap.wrap(CPE, max_line_length))

    return formatted_CPE


    

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


def create_csv(row_data):
    with open('output.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(row_data)


for row in range(2, worksheet.nrows):
    cpes = search_CPE(worksheet.cell_value(row,4), worksheet.cell_value(row,0), worksheet.cell_value(row,1), worksheet.cell_value(row,5))
    vett_cpe23Uri = [0]*len(cpes)
    vett_versionStartIncluding = [0]*len(cpes)
    vett_versionStartExcluding = [0]*len(cpes)
    vett_versionEndIncluding = [0]*len(cpes)
    vett_versionEndExcluding = [0]*len(cpes)



    if (len(cpes) > 0):
        for i in range(0, len(cpes)):
            not_null_version_types = 0
            versions_types = []
            versions_types_values = []

            vett_cpe23Uri[i] = cpes[i]["_source"]["cpe23Uri"]
            
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


            if (len(versions_types) == 1):
                cves.append(search_CVE_from_single_limit(vett_cpe23Uri[i], versions_types[0], versions_types_values[0]))
            elif (len(versions_types) == 2):
                cves.append(search_CVE_from_interval(vett_cpe23Uri[i], versions_types, versions_types_values[0], versions_types_values[1]))
            else:
                cves.append(search_CVE(vett_cpe23Uri[i]))
            
            


            #cves = search_CVE( vett_cpe23Uri[i], vett_versionStartIncluding[i], vett_versionStartExcluding[i], vett_versionEndIncluding[i], vett_versionEndExcluding[i])
        #search_exploits(row)

csv_data.append(
            [   
                "CPE",
                "CVE",
                "SCORE",
                "SEVERITY",
                "DESCRIPTION",
                "URLs",
                "REMEDIATIONS",
                "CWE"  
            ]
        )


  
for cve in cves:

    vett_URLs = []
    vett_remediations = []
    severity = ""
    impactScore = 0

    if (len(cve) > 0):
        description = format_description(cve[0]['_source']['description']['description_data'][0]['value'], 60)
        cpe = format_CPE(cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'], 40)

        for obj in cve[0]['_source']['references']['reference_data']:
            if("Vendor Advisory" in obj["tags"]):
                vett_remediations.append(obj["url"])
            vett_URLs.append(obj["url"])

        URLs_witouth_commas = delete_commas(str(vett_URLs))
        #print(URLs_witouth_commas)
        #URLs = format_URL(URLs_witouth_commas, 70)
        remediations_witouth_commas = delete_commas(str(vett_remediations))
        URLs = format_URLs(URLs_witouth_commas)
        remediations = format_URLs(remediations_witouth_commas)


        if ("baseMetricV3" in cve[0]['_source']):
            severity = cve[0]['_source']['baseMetricV3']['cvssV3']['baseSeverity']
            impactScore = cve[0]['_source']['baseMetricV3']['cvssV3']['baseScore']
        else:
            severity = severity = cve[0]['_source']['baseMetricV2']['severity']
            impactScore = cve[0]['_source']['baseMetricV2']['impactScore']

        data.append(
            [
                colorize(cpe),
                colorize(cve[0]["_id"]),
                colorize(impactScore, color=color_cvss(impactScore), attrs="bold"),
                colorize(severity),
                colorize(description),
                colorize(URLs)
            ]
        )

        csv_data.append(
            [   
                cve[0]['_source']['vuln']['nodes'][0]['cpe_match'][0]['cpe23Uri'],
                cve[0]["_id"],
                impactScore,
                severity,
                description,
                URLs,
                remediations,
                cve[0]['_source']['problemtype']['problemtype_data'][0]['description'][0]['value']
            ]
        )

        #stampaInfo(cve[0])
    
    
        cve_edbids = searchExploits(cve[0]["_id"])
        for i in cve_edbids:
            cve_all_edbids.add(i)
    pass


for i in cve_all_edbids:
        #os.system('searchsploit '+ str(i) + ' -w 2> /dev/null')
        os.system('searchsploit '+ str(i) + ' -w >/dev/null 2>&1')


 
cli_table(columns, data, hrules=True)

create_csv(csv_data)