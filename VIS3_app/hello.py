#!/usr/bin/env python3

from flask import Flask, jsonify, render_template, send_file, request
import os
import subprocess 
from random import randint
import pdfkit

index = 0

app = Flask(__name__)

@app.route('/')
def main():
    return render_template("home.html")


@app.route("/searchingCard.html")
def searchingCard():
    return render_template("searchingCard.html")

@app.route("/form.html")
def form():
    return render_template("form.html")

"""
@app.route('/createIndex')
def createIndex():
    index = 'index' + str(randint(1, 100))
    os.system("./main_gui.py {0}".format(index))
    #os.system("./main_gui.py {0}".format(request.args.get('index', None)))
    return render_template("home.html")
"""


@app.route('/downloadFunction')
def downloadFunction():
	path = "SearchingCard.xlsx"
	return send_file(path, as_attachment=True)


@app.route('/exportCSV')
def exportCSV():
	path = "output.csv"
	return send_file(path, as_attachment=True)


@app.route('/exportPDF')
def exportPDF():
    pdfkit.from_url('http://3.225.242.97:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/', 'out.pdf')	
    path = "out.pdf"
    return send_file(path, as_attachment=True)


@app.route('/returnLinks')
def returnLinks():
    global index
    index = index + 1
    kibana_index = 'index' + str(index)
    #os.system("./main_gui.py {0}".format(kibana_index))
    #path = "SearchingCard.xlsx"
    return render_template("results.html", summaryDashboardLink="http://3.225.242.97:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/", vulnerabilityReportLink="http://3.225.242.97:5601/app/kibana#/dashboard/c4cf3880-f341-11ea-950f-fba5732a37f6/", exploitViewLink="http://3.225.242.97:5601/app/kibana#/dashboard/bfafb2f0-f344-11ea-950f-fba5732a37f6/")
