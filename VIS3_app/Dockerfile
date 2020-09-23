FROM ubuntu:18.04

#Set variabili d'ambiente per Timezone (evita interattivo) Flask e Character-set di default (exploitdb)
ENV TZ=Europe/Rome
ENV FLASK_APP=/app/hello.py
ENV FLASK_ENV=development
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

#Setup timezone - evita apt interattivo
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

#Installa dipendenze
RUN apt-get update -y
RUN apt-get install python3-pip idle3 git -y

#Installa exploitdb per ricerca cve_searchsploit
RUN git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
RUN ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

#Esegue il download del db degli exploit
RUN cve_searchsploit -u

#Aggiorna pip
RUN pip3 install --no-cache-dir --upgrade pip

#Copia contenuto di VIS3 in container
COPY . /app
WORKDIR /app

#Installa dipendenze Python
RUN pip3 install -r requirements.txt

#Avvia server Docker
CMD python3 -m flask run --host=0.0.0.0