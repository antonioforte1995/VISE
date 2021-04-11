mkdir -p /tmp/upload
export FLASK_APP=./hello.py
export FLASK_ENV=production
flask run --host=0.0.0.0
