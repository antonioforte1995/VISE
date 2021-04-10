cd VIS3/VIS3_app/
source venv/bin/activate
mkdir -p /tmp/upload
export FLASK_APP=$HOME/VIS3/VIS3_app/hello.py
export FLASK_ENV=production
flask run --host=0.0.0.0
