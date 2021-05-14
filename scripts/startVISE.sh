mkdir -p /tmp/upload
export FLASK_APP=./main_gui.py
export FLASK_ENV=production
flask run --host=localhost
