#!/usr/bin/env python3
import os
import json
from pprint import pprint
import requests
import uuid

def create_dashboards(index):
    #-------------------------------
    #VULNERABILITY SUMMARY DASHBOARD
    #-------------------------------
    x = index.split("_")
    index_number = x[1] if len(x)>1 else index

    #urlzDashboardFatteBene = [""]

    #Dashboard Vulnerability Summary
    summaryID = index_number + "_s"
    summaryPanels = [ (summaryID + str(i)) for i in range(4)]
    summaryIndexPattern = summaryID + "_ip"

    summaryData = None

    import os
    cwd = os.getcwd()
    print(cwd)
    folderName = ""
    if not os.path.exists(os.path.join(cwd, "summary.json")) and os.path.exists(os.path.join(cwd, "VIS3_app/summary.json")):
        folderName = "VIS3_app/"
    with open(folderName + "summary.json") as sumFile:
        summaryData = json.load(sumFile)
    
    if summaryData == None:
        print("Failed to load JSON Summary file!!!")
    
    summaryData['objects'][0]['id'] = summaryID
    summaryData['objects'][0]['attributes']['title'] += "_" + index_number

    for i in range(len(summaryPanels)):
        summaryData['objects'][0]['references'][i]['id'] = summaryPanels[i]
        summaryData['objects'][i+1]['id'] = summaryPanels[i]
    
    for i in range(1,len(summaryPanels)):
        summaryData['objects'][i+1]['references'][0]['id'] = summaryIndexPattern
    
    summaryData['objects'][5]['id'] = summaryIndexPattern
    summaryData['objects'][5]['attributes']['title'] = index
    # summaryID coincide con l'id da concatenare al link per la dashboard di Kibana

    #Dashboard Vulnerability Technical Description
    technicalID = index_number + "_t"
    technicalPanels = [ (technicalID + str(i)) for i in range(3)]
    technicalIndexPattern = technicalID + "_ip"

    technicalData = None
    
    with open(folderName + "technical.json") as technicalFile:
        technicalData = json.load(technicalFile)
    
    if technicalData == None:
        print("Failed to load JSON technical file!!!")
    
    technicalData['objects'][0]['id'] = technicalID
    technicalData['objects'][0]['attributes']['title'] += "_" + index_number

    for i in range(len(technicalPanels)):
        technicalData['objects'][0]['references'][i]['id'] = technicalPanels[i]
        technicalData['objects'][i+1]['id'] = technicalPanels[i]
    
    for i in range(1,len(technicalPanels)):
        technicalData['objects'][i+1]['references'][0]['id'] = technicalIndexPattern
    
    technicalData['objects'][4]['id'] = technicalIndexPattern
    technicalData['objects'][4]['attributes']['title'] = index
    # technicalID coincide con l'id da concatenare al link per la dashboard di Kibana

    #Dashboard Vulnerability exploit Description
    exploitID = index_number + "_e"
    exploitPanels = [ (exploitID + str(i)) for i in range(3)]
    exploitIndexPattern = exploitID + "_ip"

    exploitData = None
    
    with open(folderName + "exploit.json") as exploitFile:
        exploitData = json.load(exploitFile)
    
    if exploitData == None:
        print("Failed to load JSON exploit file!!!")
    
    exploitData['objects'][0]['id'] = exploitID
    exploitData['objects'][0]['attributes']['title'] += "_" + index_number

    for i in range(len(exploitPanels)):
        exploitData['objects'][0]['references'][i]['id'] = exploitPanels[i]
        exploitData['objects'][i+1]['id'] = exploitPanels[i]
    
    for i in range(1,len(exploitPanels)):
        exploitData['objects'][i+1]['references'][0]['id'] = exploitIndexPattern
    
    exploitData['objects'][4]['id'] = exploitIndexPattern
    exploitData['objects'][4]['attributes']['title'] = index
    # exploitID coincide con l'id da concatenare al link per la dashboard di Kibana

    """
    os.system('curl -k -XGET \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/export?dashboard=4500b700-f341-11ea-950f-fba5732a37f6\' -u elastic:changeme 1> vsd.json')

    with open('vsd.json') as json_file:
        data = json.load(json_file)

        vsd_randomic_id = uuid.uuid1()

        data['objects'][0]['id'] = str(vsd_randomic_id)
        data['objects'][0]['attributes']['title'] ="VULNERABILITY SUMMARY DASHBOARD_{0}".format(index_number)

        for i in range(2,5):
            data['objects'][i]['references'][0]['id']="{0}".format(index)
        
        data['objects'][4]['attributes']['title']="{0}".format(index)
        data['objects'][5]['id']="{0}".format(index)


    with open('vsd.json', 'w') as outfile:
        json.dump(data, outfile)

    #---------------------------------------------
    #VULNERABILITY TECHNICAL DESCRIPTION DASHBOARD

    #---------------------------------------------
    os.system('curl -k -XGET \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/export?dashboard=c4cf3880-f341-11ea-950f-fba5732a37f6\' -u elastic:changeme 1> vtd.json')

    with open('vtd.json') as json_file:
        data = json.load(json_file)
        vtd_randomic_id = uuid.uuid1()

        data['objects'][0]['id'] = str(vtd_randomic_id)
        data['objects'][0]['attributes']['title'] ="VULNERABILITY TECHNICAL DESCRIPTION DASHBOARD_{0}".format(index_number)
        
        for i in range(2,4):
            data['objects'][i]['references'][0]['id']="{0}".format(index)

        data['objects'][4]['id']="{0}".format(index)
        data['objects'][4]['attributes']['title']="{0}".format(index)

    with open('vtd.json', 'w') as outfile:
        json.dump(data, outfile)
        

    #----------------------
    #EXPLOIT VIEW DASHBOARD
    #----------------------
    os.system('curl -k -XGET \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/export?dashboard=ffb2dc74-fcb0-11ea-ba23-000c29533237\' -u elastic:changeme 1> ev.json')

    with open('ev.json') as json_file:
        data = json.load(json_file)
        ev_randomic_id = uuid.uuid1()

        data['objects'][0]['id'] = str(ev_randomic_id)

        data['objects'][0]['attributes']['title'] ="EXPLOIT VIEW DASHBOARD_{0}".format(index_number)
        
        for i in range(2,4):
            data['objects'][i]['references'][0]['id']="{0}".format(index)

        data['objects'][4]['attributes']['title']="{0}".format(index)
        data['objects'][4]['id']="{0}".format(index)


    with open('ev.json', 'w') as outfile:
        json.dump(data, outfile)

        
    os.system('curl -u elastic:changeme -k -XPOST \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/import\' -H \'Content-Type: application/json\' -H "kbn-xsrf: true" -d @vsd.json')
    os.system('curl -u elastic:changeme -k -XPOST \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/import\' -H \'Content-Type: application/json\' -H "kbn-xsrf: true" -d @vtd.json')
    os.system('curl -u elastic:changeme -k -XPOST \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/import\' -H \'Content-Type: application/json\' -H "kbn-xsrf: true" -d @ev.json')
    """

    r1 = requests.post("http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=technicalData)
    print(r1)
    print(r1.text)

    r2 = requests.post("http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=summaryData)
    print(r2)
    print(r2.text)

    r3 = requests.post("http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=exploitData)
    print(r3)
    print(r3.text)

    vett_dashboards_links = ['http://3.225.242.97:5601/app/kibana#/dashboard/{0}'.format(summaryID), 'http://3.225.242.97:5601/app/kibana#/dashboard/{0}'.format(technicalID), 'http://3.225.242.97:5601/app/kibana#/dashboard/{0}'.format(exploitID)]
    return vett_dashboards_links


if __name__ == "__main__":
    pprint(create_dashboards("index_12345"))