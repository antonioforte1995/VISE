# ISEV
ISEV is a tool used to harvest OSINT (NVD, CVE Details, Exploit DB) aimed to aggregate informations about known vulnerabilities.

## Prerequisites
1) Linux distribution (Ubuntu 18:04 LTS preferred)
2) docker
```
cd ISEV/scripts/
sudo ./installDockerUbuntu.sh

(the script also start Kibana and Elasticsearch containers with docker-compose)
(kibana starts at http://localhost:5601)
(the username is "elastic", the password is "changeme")
```
3) exploitdb
```
sudo ./installExploitDB.sh
searchsploit -u
```
4) python3, idle3
```
sudo ./installOthers.sh
```
5) flask
```
sudo ./installFlask.sh
```


## Una tantum configurations
1) upload indexes in elasticsearch
```
sudo ./ uploadIndeces.sh
```

## Execute
1) start ISEV
```
sudo ./startISEV.sh
```
