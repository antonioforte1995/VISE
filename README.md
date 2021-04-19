# ISEV (Information Search Engine on Vulnerabilities)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-5-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

ISEV is a search engine on information delivered by OSINT (NVD, CVE Details, Exploit DB) to support Vulnerability Assessment.
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/Home.JPG?token=AO6ZS5VH5JHQA5DLN677PD3APU5D2)

The information can be exctracted by:

 1) manually filling a form:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/Form.JPG?token=AO6ZS5U4FSZFII4MWICLKHTAPUY5Y)

 2) uploading a searching card:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/Searching_Card.JPG?token=AO6ZS5VBI2C4FH2JJEO6GSDAPUZFC)

As a result, in both cases can be obtained three dashboards hosted on Kibana, describing respectivelly:

  - a summary on found vulnerabilities:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/Summary_Dashboard.JPG?token=AO6ZS5SAGLL267URGKTKVMTAPUZYY)

  - a more deep description about ones:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/Description_Dashboard.JPG?token=AO6ZS5QK643T55I3MW7Y3PTAPUZQI)

  - the available exploits for them:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/Exploit_Dashboard.JPG?token=AO6ZS5TFHXVZOFUL6X6TQP3APU4LC)

Moreover, it is possible to export those kinds of data as a unified CSV so that they can be easily managed and reviewed.

ISEV can be also used from the CLI, showing the results in a minimal and effective TUI.
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/ISEV_app/static/assets/img/scenery/TUI.JPG?token=AO6ZS5SSVIRALULD273JTDLAPU3XA)

## Prerequisites
1) Linux distribution (Ubuntu 18:04 LTS preferred)
2) python3, idle3
```
cd ISEV/scripts/
sudo ./installOthers.sh
```
3) flask
```
cd ../ISEV_app/
source venv/bin/activate
sudo ../scripts/installFlask.sh
```
4) exploitdb
```
sudo ../scripts/installExploitDB.sh
searchsploit -u
sudo cve_searchsploit -u
```
5) docker
```
sudo ../scripts/installDockerUbuntu.sh

(the script also start Kibana and Elasticsearch containers with docker-compose)
(kibana starts at http://localhost:5601)
(the username is "elastic", the password is "changeme")
```


## Una tantum configurations
1) upload indexes in elasticsearch
```
sudo ../scripts/uploadIndexes.sh
```

## Execute
1) start ISEV
```
cd ISEV/ISEV_app/
source venv/bin/activate
sudo ../scripts/startISEV.sh
```
## Contributors


<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/antonioforte1995"><img src="https://avatars.githubusercontent.com/u/62757238?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Antonio Forte</b></sub></a><br />
    </td>
    <td align="center"><a href="https://github.com/SalScotto"><img src="https://avatars.githubusercontent.com/u/34351057?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Salvatore Scotto di Perta</b></sub></a><br />
    </td>
    <td align="center"><a href="https://github.com/fabiom95"><img src="https://avatars.githubusercontent.com/u/63059167?v=4?s=100" width="100px;" alt=""/><br /><sub><b>fabiom95
</b></sub></a><br />
    </td>
    <td align="center"><a href="https://github.com/glkhan"><img src="https://avatars.githubusercontent.com/u/63093332?v=4?s=100" width="100px;" alt=""/><br /><sub><b>glkhan</b></sub></a><br />
    </td>
    </td>
    <td align="center"><a href="https://github.com/giuseppesiani"><img src="https://avatars.githubusercontent.com/u/22540856?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Giuseppe Siani</b></sub></a><br />
    </td>
  </tr>
</table>

<!-- markdownlint-enable -->
<!-- prettier-ignore-end -->
<!-- ALL-CONTRIBUTORS-LIST:END -->

## License
This project is under the **MIT license**
