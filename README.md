# ISEV (Information Search Engine on Vulnerabilities)
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
