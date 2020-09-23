FROM ubuntu:18.04

ENV TZ=Europe/Rome
ENV FLASK_APP=/app/hello.py
ENV FLASK_ENV=development
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update -y
RUN apt-get install python3-pip idle3 git -y

RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
RUN ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

RUN pip3 install --no-cache-dir --upgrade pip

COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
RUN cve_searchsploit -u

CMD python3 -m flask run --host=0.0.0.0