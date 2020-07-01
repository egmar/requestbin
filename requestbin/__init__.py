import os
import json

from io import StringIO
from flask import Flask, session, request, render_template, make_response

from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from . import config
from .filters import *

from requestbin.db import db


class WSGIRawBody(object):
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        length = environ.get('CONTENT_LENGTH', '0')
        length = 0 if length == '' else int(length)

        body = environ['wsgi.input'].read().decode('UTF-8')
        environ['raw'] = body
        environ['wsgi.input'] = StringIO(body)

        # Call the wrapped application
        app_iter = self.application(environ, self._sr_callback(start_response))

        # Return modified response
        return app_iter

    def _sr_callback(self, start_response):
        def callback(status, headers, exc_info=None):
            # Call upstream start_response
            start_response(status, headers, exc_info)

        return callback


app = Flask(__name__)

if os.environ.get('ENABLE_CORS', config.ENABLE_CORS):
    cors = CORS(app, resources={r"*": {"origins": os.environ.get('CORS_ORIGINS', config.CORS_ORIGINS)}})

app.wsgi_app = WSGIRawBody(ProxyFix(app.wsgi_app))

app.debug = config.DEBUG
app.secret_key = config.FLASK_SESSION_SECRET_KEY
app.root_path = os.path.abspath(os.path.dirname(__file__))

if config.BUGSNAG_KEY:
    import bugsnag
    from bugsnag.flask import handle_exceptions

    bugsnag.configure(
        api_key=config.BUGSNAG_KEY,
        project_root=app.root_path,
        # 'production' is a magic string for bugsnag, rest are arbitrary
        release_stage=config.REALM.replace("prod", "production"),
        notify_release_stages=["production", "test"],
        use_ssl=True
    )
    handle_exceptions(app)

app.jinja_env.filters['status_class'] = status_class
app.jinja_env.filters['friendly_time'] = friendly_time
app.jinja_env.filters['friendly_size'] = friendly_size
app.jinja_env.filters['to_qs'] = to_qs
app.jinja_env.filters['approximate_time'] = approximate_time
app.jinja_env.filters['exact_time'] = exact_time
app.jinja_env.filters['short_date'] = short_date


def update_recent_bins(name):
    if 'recent' not in session:
        session['recent'] = []
    if name in session['recent']:
        session['recent'].remove(name)
    session['recent'].insert(0, name)
    if len(session['recent']) > 10:
        session['recent'] = session['recent'][:10]
    session.modified = True


def expand_recent_bins():
    if 'recent' not in session:
        session['recent'] = []
    recent = []
    for name in session['recent']:
        try:
            recent.append(db.lookup_bin(name))
        except KeyError:
            session['recent'].remove(name)
            session.modified = True
    return recent


def _response(object, code=200):
    jsonp = request.args.get('jsonp')
    if jsonp:
        resp = make_response('%s(%s)' % (jsonp, json.dumps(object)), 200)
        resp.headers['Content-Type'] = 'text/javascript'
    else:
        resp = make_response(json.dumps(object), code)
        resp.headers['Content-Type'] = 'application/json'
        resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


@app.route('/')
def home():
    return render_template('home.html', recent=expand_recent_bins())


@app.route('/<path:name>',
           methods=['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE'])
def bin(name):
    try:
        bin = db.lookup_bin(name)
    except KeyError:
        return "Not found\n", 404
    if request.args.get('inspect'):
        if bin.private and session.get(bin.name) != bin.secret_key:
            return "Private bin\n", 403
        update_recent_bins(name)
        return render_template('bin.html',
                               bin=bin,
                               base_url=request.scheme + '://' + request.host)
    else:
        db.create_request(bin, request)
        resp = make_response("ok\n")
        resp.headers['Sponsored-By'] = "https://www.runscope.com"
        return resp


@app.route('/api/v1/bins', methods=['POST'])
def bins():
    private = request.form.get('private') in ['true', 'on']
    bin = db.create_bin(private)
    if bin.private:
        session[bin.name] = bin.secret_key
    return _response(bin.to_dict())


@app.route('/api/v1/bins/<name>', methods=['GET'])
def api_bin(name):
    try:
        bin = db.lookup_bin(name)
    except KeyError:
        return _response({'error': "Bin not found"}, 404)

    return _response(bin.to_dict())


@app.route('/api/v1/bins/<bin>/requests', methods=['GET'])
def requests(bin):
    try:
        bin = db.lookup_bin(bin)
    except KeyError:
        return _response({'error': "Bin not found"}, 404)

    return _response([r.to_dict() for r in bin.requests])


@app.route('/api/v1/bins/<bin>/requests/<name>', methods=['GET'])
def request_(bin, name):
    try:
        bin = db.lookup_bin(bin)
    except KeyError:
        return _response({'error': "Bin not found"}, 404)

    for req in bin.requests:
        if req.id == name:
            return _response(req.to_dict())

    return _response({'error': "Request not found"}, 404)


@app.route('/api/v1/stats')
def stats():
    stats = {
        'bin_count': db.count_bins(),
        'request_count': db.count_requests(),
        'avg_req_size_kb': db.avg_req_size(), }
    resp = make_response(json.dumps(stats), 200)
    resp.headers['Content-Type'] = 'application/json'
    return resp

#app.add_url_rule('/docs/<name>', 'views.docs')

# app.add_url_rule('/robots.txt', redirect_to=url_for('static', filename='robots.txt'))
