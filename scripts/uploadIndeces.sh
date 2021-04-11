cd ../ISEV_app/
source venv/bin/activate
cd ../cve-analysis
./get-cve-json.sh
./update-es.sh
cd ..
./download_cpe-match.sh
./cpe-match_indexing.py nvdcpematch-1.0.json
