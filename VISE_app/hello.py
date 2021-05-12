#!/usr/bin/env python3
from flask import Flask, jsonify, render_template, send_file, request
import os
import subprocess 
from random import randint
import pdfkit
from werkzeug.utils import secure_filename

index = 11
uploadFolder = "/tmp/upload"

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = uploadFolder

@app.route('/')
def main():
    return render_template("nhome.html")


@app.route("/searchingCard.html")
def searchingCard():
    return render_template("nsearchingCard.html")

@app.route("/form.html")
def form():
    return render_template("nform.html")


@app.route('/downloadFunction')
def downloadFunction():
	path = "SearchingCard.xlsx"
	return send_file(path, as_attachment=True)


@app.route('/exportCSV')
def exportCSV():
    filename = request.args.get("csv_name", default="output.csv", type=str)
    path = filename
    return send_file(path, as_attachment=True)


@app.route('/exportPDF')
def exportPDF():
    pdfkit.from_url('http://localhost:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/', 'out.pdf')	
    path = "out.pdf"
    return send_file(path, as_attachment=True)

@app.route('/leme')
def leme():
    filename = request.args.get("a",default="home", type=str)
    filename = "n"+filename
    if ".html" not in filename:
        filename = filename + ".html"
    return render_template(filename)

@app.route('/about')
def aboutUs():
    return render_template('about-us.html')


@app.route('/returnLinks', methods=['POST'])
#this function is used to execute the start() function that creates the dashboards on kibana with the research results
#the dashboard links are returned by this function
def returnLinks():
    global index
    index = index + 1
    import re
    from time import time
    identifier = str(int(time()))
    kibana_index = 'index_' + identifier
    if 'searchingCard' in request.files:
        f = request.files['searchingCard']
        if f.filename == '':
            print("File caricato invalido")
            return "Invalid file"
        if f and re.compile("^.*(\\.xlsx?)$").match(f.filename):
            fName = secure_filename(identifier + "_" + f.filename)
            temp = os.path.join(app.config['UPLOAD_FOLDER'], fName)
            f.save(temp)
            from main import start
            resCve = start(kibana_index, temp, True)
            print("\nCHECK RESULTS AT FOLLOWING URLs:")
            print("         {0}\n".format(resCve))
            return render_template("nresults.html",
                summaryDashboardLink=resCve[0],#"http://localhost:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/",
                vulnerabilityReportLink=resCve[1],#"http://localhost:5601/app/kibana#/dashboard/c4cf3880-f341-11ea-950f-fba5732a37f6/",
                exploitViewLink=resCve[2],#"http://localhost:5601/app/kibana#/dashboard/bfafb2f0-f344-11ea-950f-fba5732a37f6/",
                csvLink=resCve[3]
            )
    try:
        from main import start
        from json import loads as jld
        #Retrieve form data
        dati = request.form["res"]
        #I parse from JSON
        parsedData = jld(dati)
        #I launch the search function passing the array of the Form
        resCve = start(kibana_index, parsedData, False)
        #I render the page with the generated values
        print(resCve)
        return render_template("nresults.html",
            summaryDashboardLink=resCve[0],#"http://localhost:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/",
            vulnerabilityReportLink=resCve[1],#"http://localhost:5601/app/kibana#/dashboard/c4cf3880-f341-11ea-950f-fba5732a37f6/",
            exploitViewLink=resCve[2],#"http://localhost:5601/app/kibana#/dashboard/bfafb2f0-f344-11ea-950f-fba5732a37f6/",
            csvLink=resCve[3]
        )
    except Exception as e:
        print("AAAA")
        print(e)
        return e
    

