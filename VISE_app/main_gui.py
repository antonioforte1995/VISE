#!/usr/bin/env python3
from flask import Flask, render_template, send_file, request
import os
from werkzeug.utils import secure_filename

# instantiate WSGI application
app = Flask(__name__)

# to upload files (searchingCards) working with Flask
uploadFolder = "/tmp/upload"
app.config['UPLOAD_FOLDER'] = uploadFolder


# a route() decorator tells Flask what URL should trigger a specific function
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
# this function is used to execute the start() function that creates the dashboards on kibana with the research results
# the dashboard links are returned by this function
def returnLinks():
    import re
    from time import time
    identifier = str(int(time()))
    elasticsearch_index = identifier
    # if we have uploaded a searchingCard..
    if 'searchingCard' in request.files:
        f = request.files['searchingCard']
        if f.filename == '':
            print("Invalid uploaded file")
            return "Invalid file"
            # if filename is vald (.xlsx is present its name)
        if f and re.compile("^.*(\\.xlsx?)$").match(f.filename):
            # permits to pass filename to os.path.join()
            fName = secure_filename(identifier + "_" + f.filename)
            temp = os.path.join(app.config['UPLOAD_FOLDER'], fName)
            # save the file permanently somewhere on the filesystem
            f.save(temp)
            from main import start
            # launch the search function by uploading Searching Card
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
        # Retrieve form data
        data = request.form["res"]
        # parse from JSON to python dictionary
        parsedData = jld(data)
        # launch the search function passing the array of the Form
        report_links = start(elasticsearch_index, parsedData, False)
        # render the page with the generated values
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
	return send_file("static/assets/SearchingCards/SearchingCardSample.xlsx", as_attachment=True)


@app.route('/exportCSV')
def exportCSV():
    # build filename of the file (CSV output file) to be sent to client
    filename = request.args.get("csv_name", default="output.csv", type=str)
    return send_file(filename, as_attachment=True)