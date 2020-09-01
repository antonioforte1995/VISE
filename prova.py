#!/usr/bin/env python3
import re

def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)



'''
This file will be used for testing some functions.
'''
"""
import csv

def create_csv(row_data):
    with open('useless.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(row_data)
"""

import subprocess
output = subprocess.check_output("searchsploit Citrix Metaframe 1.8 -w", shell=True)


string_output = output.decode('utf-8')
splitted_string = string_output.split("\n")

URLs = []

for i in range(3, len(splitted_string)-4):
    URLs.append(escape_ansi(splitted_string[i].split('|')[-1]))
    #print(splitted_string[i].split('|')[-1])

print(URLs)
