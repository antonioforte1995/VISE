#!/usr/bin/env python3

from flask import Flask, jsonify, render_template, send_file, request
import os
import subprocess 
from random import randint
import pdfkit

#pdfkit.from_url('http://elastic:changeme@3.225.242.97:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6?_g=(filters:!(),refreshInterval:(pause:!f,value:10000),time:(from:now-1h,to:now))&_a=(description:'',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:''),timeRestore:!f,title:\'VULNERABILITY%20SUMMARY%20DASHBOARD\',viewMode:view)', 'out.pdf')
#os.system('curl -o out.html \'http://elastic:changeme@3.225.242.97:5601/api/kibana/dashboards/export?dashboard=4500b700-f341-11ea-950f-fba5732a37f6\' -u elastic:changeme')

#os.system('curl -k -XGET \'http://elastic:chageme@3.225.242.97:5601/api/kibana/dashboards/export?dashboard=4500b700-f341-11ea-950f-fba5732a37f6\' -u elastic:changeme > export.json')

"""
context = json.load(open("export.json"))

rendered_string = render_to_string("template.html", context)

HTML(string=rendered_string).write_pdf("out.pdf")
"""

def exportPDF():
    pdfkit.from_url('https://www.google.com/', 'out.pdf')	
    path = "out.pdf"
    return send_file(path, as_attachment=True)


exportPDF()