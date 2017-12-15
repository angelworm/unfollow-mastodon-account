#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import requests_toolbelt.adapters.appengine

requests_toolbelt.adapters.appengine.monkeypatch()
import tempfile
tempfile.SpooledTemporaryFile = tempfile.TemporaryFile

from google.appengine.ext import ndb as db
from google.appengine.api import memcache

from flask import Flask, render_template, redirect, url_for, request, jsonify, session, g
import logging
import time
import random
import json
import requests

app = Flask(__name__)

logger = logging.getLogger(__name__)

app.secret_key = 'ddrrnexzugfxqzlcjwktiqcsjmmikibpykfkrjkpxwsnwzliyiziprlvywvgpzhqutddlcraouqjjnvhdyilvgxtqddbunbsznduzotyavelfiefwccxqrko'

class MastodonClient(db.Model):
    domain = db.StringProperty()
    client_id = db.StringProperty()
    client_secret = db.StringProperty()

def fetch_client(domain):
    cache_key = 'client:' + domain
    ret = memcache.get(cache_key)

    if ret is not None:
        return ret

    ret = MastodonClient.query(MastodonClient.domain == domain).fetch(1)

    if len(ret) != 0:
        ret = ret[0]
        memcache.set(cache_key, ret)
        return ret

    return None

def gen_apps(domain, redirect):
    url = 'https://%s/api/v1/apps' % domain

    try:
        res = requests.post(url, params = {
            'client_name': '死者にたいする最高の手向けは、悲しみではなく感謝だ。',
            'redirect_uris': redirect,
            'scopes': 'read follow'
        })

        data = res.json()

        client = MastodonClient(
            domain = domain,
            client_id = data['client_id'],
            client_secret = data['client_secret']
        )
        client.put()
        
        return client
    except:
        logging.exception('Failed to create Applications')
        return None
    
class Session(db.Model):
    session_id = db.StringProperty()
    user_name = db.StringProperty()
    domain = db.StringProperty()
    access_token = db.StringProperty()
    created = db.IntegerProperty()
    
def gen_session_id():
    chars = list(chr(x) for x in range(ord('a'), ord('z') + 1))
    return ''.join(random.choice(chars) for i in range(120))

def fetch_session(session_id):
    cache_key = 'session:' + session_id
    ret = memcache.get(cache_key)

    if ret is None:
        ret = Session.query(Session.session_id == session_id).fetch(1)
        ret = ret[0] if len(ret) > 0 else None

    if ret is None:
        ret = Session(session_id = session_id)

    memcache.set(cache_key, ret)
    return ret

def put_session(session):
    cache_key = 'session:' + session.session_id
    
    session.put()
    memcache.set(cache_key, session)

def post(session, path, params=None):
    url = 'https://%s/%s' % (session.domain, path)

    headers = None
    if session.access_token is not None:
        headers = {
            'Authorization': 'Bearer %s' % session.access_token
        }
        
    return requests.post(url, params=params, headers=headers).json()

def get(session, path, params=None):
    url = 'https://%s/%s' % (session.domain, path)

    headers = None
    if session.access_token is not None:
        headers = {
            'Authorization': 'Bearer %s' % session.access_token
        }
        
    return requests.get(url, params=params, headers=headers).json()
    
@app.errorhandler(500)
def server_error(e):
    logging.exception('An error occurred during a request.')
    return """
    An internal error occurred: <pre>{}</pre>
    See logs for full stacktrace.
    """.format(e), 500

@app.before_request
def check_session():
    s = session.get('session_id', gen_session_id())
    session['session_id'] = s
    g.session = fetch_session(s)

@app.route('/')
def root():
    if g.session.access_token is None:
        return render_template('login.html')

    if g.session.user_name is None:
        account = get(g.session, 'api/v1/accounts/verify_credentials')
        g.session.user_name = account.get('acct')
        put_session(g.session)
    if g.session.user_name is None:
        return render_template('login.html')
        
    session['user_name'] = '@%s@%s' % (g.session.user_name, g.session.domain)
    
    return render_template('index.html')
    
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return redirect(url_for('root'))
    
    accr = request.form.get('account', '').split('@')
    accr = list(a for a in accr if a != '')

    if len(accr) != 2:
        return redirect(url_for('root'))
    
    name = accr[0]
    domain = accr[1]
    redirect_target = request.host_url + 'auth'
    
    client = fetch_client(domain)
    if client is None:
        client = gen_apps(domain, redirect_target)
    if client is None:
        return redirect(url_for('root'))

    g.session.domain = domain
    put_session(g.session)
    
    auth_url = 'https://%s/oauth/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=read%%20follow' % (domain, client.client_id, redirect_target)
    return redirect(auth_url)

@app.route('/auth', methods=['GET'])
def auth():
    code = request.args.get('code')
    domain = g.session.domain
    redirect_target = request.host_url + 'auth'

    if code is None or domain is None:
        return redirect(url_for('root'))

    client = fetch_client(domain)
    
    url = 'https://%s/oauth/token' % domain
    data = post(g.session, 'oauth/token', {
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_target,
        'client_id': client.client_id,
        'client_secret': client.client_secret,
        'code': code
    })

    try:
        g.session.access_token = data['access_token']
        g.session.created = data['created_at']
        put_session(g.session)
    except:
        print(data, client, code, redirect_target)
        raise

    return redirect(url_for('root'))

@app.route('/kill', methods=['GET'])
def kill():
    data = post(g.session, 'api/v1/accounts/409/unfollow')

    return redirect(url_for('root'))

@app.route('/logout', methods=['GET'])
def logout():
    del session['session_id']
    g.session = None
    
    return redirect(url_for('root'))
