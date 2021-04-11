# ISEV
ISEV is a tool used to harvest OSINT (NVD, CVE Details, Exploit DB) aimed to aggregate informations about known vulnerabilities.

## Prerequisites
1) Linux distribution (Ubuntu 18:04 LTS preferred)
2) docker
```
cd ISEV/scripts/
sudo ./installDockerUbuntu.sh
(the script also start Kibana and Elasticsearch containers with docker-compose, start una tantum because of restart always associated to containers in docker-compose)
(kibana starts at http://localhost:5601)
(the username is "elastic", the password is "changeme")
```
3) exploitdb
```
sudo ./installExploitDB.sh
```
4) python3, idle3, git
```
sudo ./installOthers.sh
```
5) flask
```
cd VIS3_app/
sudo ./installFlask.sh
```


## Una tantum configurations
1) upload indexes in elasticsearch
```
sudo ./ uploadIndeces.sh
```

## Execute
1) start VIS3
```
sudo ./startISEV.sh
```
