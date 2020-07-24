#!/usr/bin/env python3
import xlrd
from query import *
from enrichment import *
import os
  

workbook = xlrd.open_workbook('/home/antonio/Scrivania/VIS3/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)

cve_all_edbids = set()


def search_exploits(row):
    os.system('searchsploit '+ worksheet.cell_value(row,3) + ' ' + worksheet.cell_value(row,1) +  ' ' + worksheet.cell_value(row,5) + ' -w')
    os.system('searchsploit '+ worksheet.cell_value(row,3) + ' ' + worksheet.cell_value(row,1) +  ' ' + 'Multiple -w')
    

for row in range(worksheet.nrows-2, worksheet.nrows-1):
    #print('cpe:2.3:{0}:{1}:{2}:{3}:*'.format('*', '*', worksheet.cell_value(1,col), worksheet.cell_value(2,col)))
    cves = ricercaCVE('cpe:2.3:{0}:{1}:{2}:{3}:*'.format('*', '*', worksheet.cell_value(row,0), worksheet.cell_value(row,1)))
    #search_exploits(row)
    
    
    for cve_all in cves:
        #print(cve_all["_id"])
        #stampaInfo(cve_all)
        cve_edbids = searchExploits(cve_all["_id"])
        for i in cve_edbids:
            cve_all_edbids.add(i)

    print("All Edbids for all CVE: {0}".format(cve_all_edbids)) 


    for i in cve_all_edbids:
            os.system('searchsploit '+ str(i) + ' -w')
    print()
    pass