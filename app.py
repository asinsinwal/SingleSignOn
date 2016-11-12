from flask import Flask, redirect,render_template, url_for, session ,jsonify , request
from flask_oauth import OAuth
from flask_api import status
from flask_cors import CORS, cross_origin
import uuid
import json
import xlrd
import numpy as np
import csv
import logging

import sqlite3 as sqllite
import sys 
 
# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = '245606374074-3j3dt03ik1jjcbhbrduaod5ar85d5dh7.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'GpJsby_uiUebnqO11vWq4rBf'
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console
 
SECRET_KEY = 'development key'
DEBUG = True
 
app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()
 

configTable = {}
cur = None
con = None

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)

def setup_sql_lite_db():
    try:

        global con
        con = sqllite.connect('identity_json.db', check_same_thread=False)
        global cur
        cur = con.cursor()
        #cur.execute('DROP TABLE IF EXISTS Comment')
        sql = "CREATE TABLE IF NOT EXISTS Identity (" \
              "    id VARCHAR, " \
              "    email TEXT," \
	      "    verified VARCHAR," \
              "    hd VARCHAR )"
        cur.execute(sql)
        con.commit()

    except sqllite.Error, e:
        print "Error %s:" % e.args[0]
        sys.exit(1)



## Json format to return web api calls

notes = {
    0: 'not verified',
    1: 'verfied',
}

def Identity_repr(key):
    return {
        'url': request.host_url.rstrip('/') + url_for('notes_detail', key=key),
        'text': identify[key]
    }


@app.route('/')
def index():
    global cur, con
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))
 
    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError
 
    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v1/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('login'))
        return res.read()
    #return render_template('developer.html')
    #cur.execute("INSERT INTO Config (id, json ) VALUES('" + str(id) + "', '" + json.dumps(request.json) + "')")
    #con.commit()
   
    data = res.read()
    json1_data = json.loads(data)

    # If not using ncsu gmail id then redirect [temporary] 	
    if 'hd' not in json1_data:
	return redirect(url_for('login'))

    cur.execute("SELECT verified FROM Identity WHERE id='" + str(json1_data["id"]) + "'")
    rows = cur.fetchall()
 
    if(len(rows)==0):
	insert(json1_data,cur,con)
    else:
	return render_template('temp.html', json_data = json1_data["id"])  ## render shortcut one 
	


   # cur.execute("INSERT INTO Identity (id, email ,verified ,hd ) VALUES('" + str(json1_data["id"]) + "', '" + str(json1_data["email"]) +"', '"
#+ str(json1_data["verified_email"]) +"', '" + str(json1_data["hd"]) +"')") 
    #con.commit()


    return data
 

def insert(json1_data,cur,con):
    cur.execute("INSERT INTO Identity (id, email ,verified ,hd ) VALUES('" + str(json1_data["id"]) + "', '" + str(json1_data["email"]) +"', '"
+ str(json1_data["verified_email"]) +"', '" + str(json1_data["hd"]) +"')") 
    con.commit()

    
def delete(json1_data,cur,con):
    cur.execute("DELETE from Identity WHERE id='" + str(json1_data["id"]) + "'")
    con.commit()



@app.route('/login')
def login():
    callback=url_for('authorized', _external=True)
    return google.authorize(callback=callback)
 
 
 
@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('index'))
 
 
@google.tokengetter
def get_access_token():
    return session.get('access_token')
 
 
def main():
    setup_sql_lite_db()
    app.run()
 
 
if __name__ == '__main__':
    main()
