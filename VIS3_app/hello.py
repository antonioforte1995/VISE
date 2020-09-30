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
    filename = request.args.get("csv_name", default="output.csv", type=str)
    path = filename
    return send_file(path, as_attachment=True)


@app.route('/exportPDF')
def exportPDF():
    pdfkit.from_url('http://3.225.242.97:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/', 'out.pdf')	
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
def returnLinks():
    global index
    index = index + 1
    #Indice attuale, necessario trovare un modo per generarlo univocamente
    #(magari effettuare una get dell'ultimo index creato)
    #from uuid import uuid1
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
            from main_gui import start
            resCve = start(kibana_index, temp, True)
            print(resCve)
            return render_template("nresults.html",
                summaryDashboardLink=resCve[0],#"http://3.225.242.97:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/",
                vulnerabilityReportLink=resCve[1],#"http://3.225.242.97:5601/app/kibana#/dashboard/c4cf3880-f341-11ea-950f-fba5732a37f6/",
                exploitViewLink=resCve[2],#"http://3.225.242.97:5601/app/kibana#/dashboard/bfafb2f0-f344-11ea-950f-fba5732a37f6/",
                csvLink=resCve[3]
            )
    try:
        from main_gui import start
        from json import loads as jld
        #Recupero i dati del form
        dati = request.form["res"]
        #Effettuo il parse da JSON
        parsedData = jld(dati)
        #Lancio la funzione di ricerca passando l'array del Form
        resCve = start(kibana_index, parsedData, False)
        #Effettuo il render della pagina con i valori generati
        print(resCve)
        return render_template("nresults.html",
            summaryDashboardLink=resCve[0],#"http://3.225.242.97:5601/app/kibana#/dashboard/4500b700-f341-11ea-950f-fba5732a37f6/",
            vulnerabilityReportLink=resCve[1],#"http://3.225.242.97:5601/app/kibana#/dashboard/c4cf3880-f341-11ea-950f-fba5732a37f6/",
            exploitViewLink=resCve[2],#"http://3.225.242.97:5601/app/kibana#/dashboard/bfafb2f0-f344-11ea-950f-fba5732a37f6/",
            csvLink=resCve[3]
        )
    except Exception as e:
        print("AAAA")
        print(e)
        return e
    
