#!/usr/bin/env python3
import colored
from prettytable import PrettyTable

def colorize(string, color=None, highlight=None, attrs=None):
    """Apply style on a string"""
    # Colors list: https://pypi.org/project/colored/
    return colored.stylize(
        string,
        (colored.fg(color) if color else "")
        + (colored.bg(highlight) if highlight else "")
        + (colored.attr(attrs) if attrs else ""),
    )

def color_cvss(cvss):
    """Attribute a color to the CVSS score"""
    #cvss = float(cvss)
    if cvss < 3:
        color = "green_3b"
    elif cvss <= 5:
        color = "yellow_1"
    elif cvss <= 7:
        color = "orange_1"
    elif cvss <= 8.5:
        color = "dark_orange"
    else:
        color = "red"
    return color


a = 5
b = 5
t = PrettyTable(['Input', 'status'])
if a == "ok":
    a = "\033[1;32m%s\033[0m" %a 
    t.add_row(['FAN', a])
else:
    colorize(b, color=color_cvss(b), attrs="bold")
    #b = "\033[1;31m%s\033[0m" %b
    t.add_row(['APPIS', b])
print(t)


#colorize(t, color=color_cvss(5), attrs="bold")
print(t)