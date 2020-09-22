#!/usr/bin/env python3
import os
import json
from prettyprinter import pprint
import uuid

def create_dashboards(index):
    #-------------------------------
    #VULNERABILITY SUMMARY DASHBOARD
    #-------------------------------
    x = index.split("_")
    index_number = x[1]

    
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


    vett_dashboards_links = ['http://3.225.242.97:5601/app/kibana#/dashboard/{0}'.format(vsd_randomic_id), 'http://3.225.242.97:5601/app/kibana#/dashboard/{0}'.format(vtd_randomic_id), 'http://3.225.242.97:5601/app/kibana#/dashboard/{0}'.format(ev_randomic_id)]
    return vett_dashboards_links