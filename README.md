# VIS3
VIS3 is a tool used to harvest OSINT (NVD, CVE Details, Exploit DB) aimed to aggregate informations about known vulnerabilities.

## Prerequisites
1) Linux distribution (Ubuntu 18:04 LTS preferred)
2) docker
```
cd VIS3/
sudo ./installDockerUbuntu.sh
```
3) exploitdb
```
sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb	
sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
searchsploit -u
```
4) python3, idle3, git
```
sudo apt-get install python3-pip idle3 git -y
```
5) flask
```
cd VIS3_app/
sudo apt install python3-venv
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
cve_searchsploit -u
pip install Flask
```


## Una tantum configurations
1) start Kibana and Elasticsearch containers with docker-compose (start una tantum because of restart always associated to containers in docker-compose)
```
cd cd ../docker-elk/
sudo docker-compose up
(kibana starts at http://localhost:5601)
(the username is "elastic", the password is "changeme")
```
2) upload indexes in elasticsearch
```
cd /VIS3/cve-analysis
./update-es.sh
(now manually create a "cve-index" index-pattern from kibana GUI)
cd ..
./download_cpe-match.sh
./cpe-match_indexing.py nvdcpematch-1.0.json
(now manually create a "cpe-index" index-pattern from kibana GUI)
```

## Execute
1) start VIS3
```
cd VIS3/VIS3_app/
source venv/bin/activate	
mkdir -p /tmp/upload
export FLASK_APP=$HOME/VIS3/VIS3_app/hello.py
export FLASK_ENV=production
flask run --host=0.0.0.0
(VIS3 app starts at http://localhost:5000)
```
