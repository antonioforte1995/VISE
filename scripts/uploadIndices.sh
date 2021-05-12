cd ../VISE_app/
source venv/bin/activate
cd ../cve-analysis
./get-cve-json.sh
./update-es.sh
cd ../scripts/
./download_cpe-match.sh
./cpe-match_indexing.py nvdcpematch-1.0.json
