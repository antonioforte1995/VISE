#!/usr/bin/env python3
import xlrd
from query import *

workbook = xlrd.open_workbook('/home/antonio/Scrivania/SearchingCard.xlsx', on_demand = True)
worksheet = workbook.sheet_by_index(0)


for col in range(3, worksheet.ncols):
    #print('cpe:2.3:{0}:{1}:{2}:{3}:*'.format('*', '*', worksheet.cell_value(1,col), worksheet.cell_value(2,col)))
    cves = ricercaCVE('cpe:2.3:{0}:{1}:{2}:{3}:*'.format('*', '*', worksheet.cell_value(1,col), worksheet.cell_value(2,col)))
    for cve_all in cves:
        stampaInfo(cve_all)
    pass

