FROM python:latest

# want all dependencies first so that if it's just a code change, don't have to
# rebuild as much of the container
ADD requirements.txt /opt/requestbin/
RUN pip install -r /opt/requestbin/requirements.txt \
    && rm -rf ~/.pip/cache

# the code
ADD requestbin  /opt/requestbin/requestbin/

EXPOSE 8000

WORKDIR /opt/requestbin
CMD gunicorn -b 0.0.0.0:8000 --worker-class gevent --workers 2 --max-requests 1000 requestbin:app


