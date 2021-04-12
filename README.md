# ISEV (Information Search Engine on Vulnerabilities)
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-5-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

ISEV is a tool used to harvest OSINT (NVD, CVE Details, Exploit DB) aimed to aggregate information about known vulnerabilities.

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
