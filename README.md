# VISE (Vulnerability Information Search Engine)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-5-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

VISE is a search engine on information delivered by OSINT sources (e.g. NVD, Exploit DB) to support Vulnerability Assessment.
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/home.PNG)

The information can be exctracted by:

 1) manually filling a form:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/form.PNG)

 2) uploading a searching card:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/searching_card.JPG)

As a result, in both cases can be obtained three dashboards hosted on Kibana, describing respectivelly:

  - a summary on found vulnerabilities:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/vulnerability_summary_dashboard.PNG)

  - a more deep description about ones:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/vulnerability_technical_description_dashboard.JPG)

  - the available exploits for them:
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/exploit_view_dashboard.JPG)

Moreover, it is possible to export those kinds of data as a unified CSV so that they can be easily managed and reviewed.

VISE can be also used from the CLI, showing the results in a minimal and effective TUI.
<!-- ![alt text] -->
![](https://raw.githubusercontent.com/antonioforte1995/ISEV/master/VISE_app/static/assets/img/scenery/TUI.jpg)

## Prerequisites
1) Linux distribution (Ubuntu 18:04 LTS preferred)
2) python3, idle3
```
cd VISE/scripts/
sudo ./installOthers.sh
```
3) flask
```
cd ../VISE_app/
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
```
(the script also start Kibana and Elasticsearch containers with docker-compose)<br />
(kibana starts at http://localhost:5601)<br />
(the username is "elastic", the password is "changeme")

## Una tantum configurations
1) upload indices in elasticsearch
```
sudo ../scripts/uploadIndices.sh
```

## Execute
1) start VISE
```
cd VISE/VISE_app/
sudo ../scripts/startVISE.sh
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

## Cite
If you use this tool in your academic work you can cite it using:
```bibtex
@misc{vise,
  author       = {Antonio Forte},
  howpublished = {GitHub},
  month        = apr,
  title        = {{VISE (Vulnerability Information Search Engine)}},
  year         = {2020},
  url          = {https://github.com/antonioforte1995/VISE},
}
```
