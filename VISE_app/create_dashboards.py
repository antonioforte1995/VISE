#!/usr/bin/env python3
import os
import json
from pprint import pprint
import requests
import uuid

def create_dashboards(index):
    x = index.split("_")
    index_number = x[1] if len(x)>1 else index

    #Dashboard Vulnerability Summary
    summaryID = index_number + "_s"
    summaryPanels = [ (summaryID + str(i)) for i in range(4)]
    summaryIndexPattern = summaryID + "_ip"

    summaryData = None

    folderName = "static/assets/json_files/"
    with open(folderName + "summary.json") as sumFile:
        summaryData = json.load(sumFile)
    
    if summaryData == None:
        pass
    
    summaryData['objects'][0]['id'] = summaryID
    summaryData['objects'][0]['attributes']['title'] += "_" + index_number

    for i in range(len(summaryPanels)):
        summaryData['objects'][0]['references'][i]['id'] = summaryPanels[i]
        summaryData['objects'][i+1]['id'] = summaryPanels[i]
    
    for i in range(1,len(summaryPanels)):
        summaryData['objects'][i+1]['references'][0]['id'] = summaryIndexPattern
    
    summaryData['objects'][5]['id'] = summaryIndexPattern
    summaryData['objects'][5]['attributes']['title'] = index
    # summaryID coincides with the id to be concatenated to the link for the Kibana dashboard

    #Dashboard Vulnerability Technical Description
    technicalID = index_number + "_t"
    technicalPanels = [ (technicalID + str(i)) for i in range(3)]
    technicalIndexPattern = technicalID + "_ip"

    technicalData = None
    
    with open(folderName + "technical.json") as technicalFile:
        technicalData = json.load(technicalFile)
    
    if technicalData == None:
        pass
    
    technicalData['objects'][0]['id'] = technicalID
    technicalData['objects'][0]['attributes']['title'] += "_" + index_number

    for i in range(len(technicalPanels)):
        technicalData['objects'][0]['references'][i]['id'] = technicalPanels[i]
        technicalData['objects'][i+1]['id'] = technicalPanels[i]
    
    for i in range(1,len(technicalPanels)):
        technicalData['objects'][i+1]['references'][0]['id'] = technicalIndexPattern
    
    technicalData['objects'][4]['id'] = technicalIndexPattern
    technicalData['objects'][4]['attributes']['title'] = index
    # technicalID coincides with the id to be concatenated to the link for the Kibana dashboard

    #Dashboard Vulnerability exploit Description
    exploitID = index_number + "_e"
    exploitPanels = [ (exploitID + str(i)) for i in range(3)]
    exploitIndexPattern = exploitID + "_ip"

    exploitData = None
    
    with open(folderName + "exploit.json") as exploitFile:
        exploitData = json.load(exploitFile)
    
    if exploitData == None:
        pass
    
    exploitData['objects'][0]['id'] = exploitID
    exploitData['objects'][0]['attributes']['title'] += "_" + index_number

    for i in range(len(exploitPanels)):
        exploitData['objects'][0]['references'][i]['id'] = exploitPanels[i]
        exploitData['objects'][i+1]['id'] = exploitPanels[i]
    
    for i in range(1,len(exploitPanels)):
        exploitData['objects'][i+1]['references'][0]['id'] = exploitIndexPattern
    
    exploitData['objects'][4]['id'] = exploitIndexPattern
    exploitData['objects'][4]['attributes']['title'] = index
    # exploitID coincides with the id to be concatenated to the link for the Kibana dashboard

    es_url = os.environ['ESURL'] if ('ESURL' in os.environ) else "http://elastic:changeme@localhost:9200"
    kibanaUrl = es_url[:-4] + "5601"
    
    requests.post(kibanaUrl + "/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=technicalData)
    requests.post(kibanaUrl + "/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=summaryData)
    requests.post(kibanaUrl + "/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=exploitData)
    
    dashUrl = kibanaUrl.split("@")
    if len(dashUrl) > 1:
        dashUrl = dashUrl[-1]
        dashUrl = "http://" + dashUrl
    else:
        dashUrl = dashUrl[0]
    

    vett_dashboards_links = [dashUrl + '/app/kibana#/dashboard/{0}'.format(summaryID), 
        dashUrl + '/app/kibana#/dashboard/{0}'.format(technicalID),
        dashUrl + '/app/kibana#/dashboard/{0}'.format(exploitID)]
    return vett_dashboards_links