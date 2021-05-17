#!/usr/bin/env python3
import json
import requests

# this script creates 3 kibana dashboards for the current search
# to make so, we start from 3 json files describing:
# 1) the summary dashboard
# 2) the technical dashboard
# 3) the exploit dashboard


def create_dashboards(elastic_index):
    dashboards_links = []    
    dashboards = ['summary_dashboard', 'technical_dashboard', 'exploit_dashboard']
    sum_dash_num_panels = 4
    sum_dash_num_objects = 6

    # each iteration creates a new dashboard
    for dashboard in dashboards:
        if (dashboard == 'summary_dashboard'):
            id = elastic_index + "_s"
            panels_ids = [ (id + str(i)) for i in range(sum_dash_num_panels)]
            indexPattern = id + "_ip"
        elif (dashboard == 'technical_dashboard'):
            id = elastic_index + "_t"
            panels_ids = [ (id + str(i)) for i in range(sum_dash_num_panels-1)]
            indexPattern = id + "_ip"
        else:
            id = elastic_index + "_e"
            panels_ids = [ (id + str(i)) for i in range(sum_dash_num_panels-1)]
            indexPattern = id + "_ip"

        data = None

        # read json file of current basic dashboard
        folderName = "static/assets/json_files/"
        with open(folderName + "{0}.json".format(dashboard)) as File:
            data = json.load(File)
        
        if data == None:
            pass
        
        # customize something for the creation of the new dashboard
        data['objects'][0]['id'] = id
        data['objects'][0]['attributes']['title'] += "_" + elastic_index

        for i in range(len(panels_ids)):
            data['objects'][0]['references'][i]['id'] = panels_ids[i]
            data['objects'][i+1]['id'] = panels_ids[i]
        
        for i in range(1,len(panels_ids)):
            data['objects'][i+1]['references'][0]['id'] = indexPattern
        
        if (dashboard == 'summary_dashboard'):
            data['objects'][sum_dash_num_objects-1]['id'] = indexPattern
            data['objects'][sum_dash_num_objects-1]['attributes']['title'] = elastic_index
        else:
            data['objects'][sum_dash_num_objects-2]['id'] = indexPattern
            data['objects'][sum_dash_num_objects-2]['attributes']['title'] = elastic_index

        # make an HTTP POST request to create a new dashboard
        requests.post("http://elastic:changeme@localhost:5601/api/kibana/dashboards/import", headers = {'kbn-xsrf': 'true'}, json=data)
        # add the URL of the just created dashboard to the dashboards_links array
        dashboards_links.append('http://localhost:5601/app/kibana#/dashboard/{0}'.format(id))

    return dashboards_links