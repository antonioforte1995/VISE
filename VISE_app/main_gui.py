#!/usr/bin/env python3
from flask import Flask, jsonify, render_template, send_file, request
import os
import subprocess 
from random import randint
import pdfkit
from werkzeug.utils import secure_filename

uploadFolder = "/tmp/upload"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = uploadFolder


@app.route('/')
def main():
    return render_template("home.html")


@app.route("/searchingCard.html")
def searchingCard():
    return render_template("searchingCard.html")


@app.route("/form.html")
def form():
    return render_template("form.html")


@app.route('/returnLinks.html', methods=['POST'])
#this function is used to execute the start() function that creates the dashboards on kibana with the research results
#the dashboard links are returned by this function
def returnLinks():
    import re
    from time import time
    identifier = str(int(time()))
    elasticsearch_index = identifier
    if 'searchingCard' in request.files:
        f = request.files['searchingCard']
        if f.filename == '':
            print("Invalid uploaded file")
            return "Invalid file"
        if f and re.compile("^.*(\\.xlsx?)$").match(f.filename):
            fName = secure_filename(identifier + "_" + f.filename)
            temp = os.path.join(app.config['UPLOAD_FOLDER'], fName)
            f.save(temp)
            from main import start
            #I launch the search function by uploading Searching Card
            report_links = start(elasticsearch_index, temp, True)
            return render_template("returnLinks.html",
                summaryDashboardLink=report_links[0],
                vulnerabilityReportLink=report_links[1],
                exploitViewLink=report_links[2],
                csvLink=report_links[3]
            )
    try:
        from main import start
        from json import loads as jld
        #Retrieve form data
        data = request.form["res"]
        #parse from JSON to python dictionary
        parsedData = jld(data)
        #launch the search function passing the array of the Form
        report_links = start(elasticsearch_index, parsedData, False)
        #render the page with the generated values
        return render_template("returnLinks.html",
            summaryDashboardLink=report_links[0],
            vulnerabilityReportLink=report_links[1],
            exploitViewLink=report_links[2],
            csvLink=report_links[3]
        )
    except Exception as e:
        print("AAAA")
        print(e)
        return e


@app.route('/downloadSearchingCardSample')
def downloadSearchingCardSample():
	path = "static/assets/SearchingCards/SearchingCardSample.xlsx"
	return send_file(path, as_attachment=True)


@app.route('/exportCSV')
def exportCSV():
    filename = request.args.get("csv_name", default="output.csv", type=str)
    path = filename
    return send_file(path, as_attachment=True)