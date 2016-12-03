from flask import Flask, redirect,render_template, url_for, session ,jsonify , request
from flask import Markup
from flask import flash
from flask_oauth import OAuth
from signup import SignupForm
import uuid
import base64
import sys
import json
import xlrd
import csv
import logging

from admin import administrator

import sqlite3 as sqllite
import sys

# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = '245606374074-3j3dt03ik1jjcbhbrduaod5ar85d5dh7.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'GpJsby_uiUebnqO11vWq4rBf'
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console

SECRET_KEY = 'development key'
DEBUG = True

isadmin = 0

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
              "    isAdmin INTEGER " \
              " calls INTEGER)"
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
    global cur, con, isadmin
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
    ''''if 'hd' not in json1_data:
        return redirect(url_for('login'))'''

    cur.execute("SELECT verified FROM Identity WHERE email='" + str(json1_data["email"]) + "'")
    rows = cur.fetchall()
    print json1_data
    print "In here"
    print rows
    print json1_data["id"]
    if(len(rows)==0):
        return redirect(url_for('signup'))
    elif(str(rows[0][0])=='0'):
            return render_template('approval.html')
    else:
        #length = 16 - ( len(json1_data["id"]) % 16 )
        #json1_data["id"] += bytes([length])*length
        update(json1_data,cur,con)
        encoded = base64.b64encode(json1_data["id"])
        print 'encoded'
        print encoded
        print 'decoded'
        print base64.b64decode(encoded)
        json1_data["id"] = encoded
        cur.execute("SELECT isAdmin,calls FROM Identity WHERE email='" + str(json1_data["email"]) + "'")
        rows = cur.fetchall()
        print rows[0][0]
        print rows[0][1]
        json1_data["isAdmin"] = rows[0][0]

        isadmin = rows[0][0]
        json1_data["calls"] = rows[0][1]
        return render_template('temp.html', data = json1_data)  ## render shortcut one

    return render_template('temp.html', data = json1_data)



   # cur.execute("INSERT INTO Identity (id, email ,verified ,hd ) VALUES('" + str(json1_data["id"]) + "', '" + str(json1_data["email"]) +"', '"
#+ str(json1_data["verified_email"]) +"', '" + str(json1_data["hd"]) +"')")
    #con.commit()
@app.route('/signup')
def signup():
   form = SignupForm()
   return render_template('signup.html', form = form)

@app.route('/logout')
def logout():
    return render_template('logout.html')

@app.route('/approval')
def approval():
    return render_template('approval.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = SignupForm()
    if request.method == 'POST':
            global cur,con
            email = form.email.data
            json = {}
            json["email"] = str(email)
            json["verified"] = 0
            json["id"] = None
            json["isAdmin"] = 0
            json["calls"] = 20
            print json
            insert(json,cur,con)
            return redirect('/approval')

@app.route("/<int:key>/", methods=['GET'])
def developer(key):
    global cur, con
    print 'before db query'+str(key)
    key = str(key)
    cur.execute("SELECT verified FROM Identity WHERE id='" + key + "'")
    rows = cur.fetchall()
    if(len(rows)==0):
        return render_template('error.html')  ## render shortcut one
    else:
        cur.execute("SELECT calls FROM Identity WHERE id='" + key + "'")
        calls = cur.fetchall()
        no_calls = int(calls[0][0])
        if (no_calls <= 0):
            return redirect('/')
        else:
            no_calls = int(calls[0][0]) - int(1)
            cur.execute("Update Identity SET calls = '" + str(no_calls) + "' WHERE id='" + key + "'")
            con.commit()
            return "true"  ## render shortcut one


@app.route("/delete_token", methods=['GET'])
def delete_token():
    global cur, con
    key = request.args.get('id')
    cur.execute("UPDATE Identity set id = 'None' WHERE id='" + str(key) + "'")
    con.commit()
    session.pop('access_token', None)
    return redirect(url_for('logout'))

    #return render_template('temp.html', json_data = key)  ## render shortcut one
def insert(json1_data,cur,con):
    cur.execute("INSERT INTO Identity (id, email ,verified, isAdmin, calls ) VALUES('" + str(json1_data["id"]) + "', '" + str(json1_data["email"]) +"', '"
+ str(json1_data["verified"]) +"', '" + str(json1_data["isAdmin"]) +"', '" + str(json1_data["calls"]) +"')")
    con.commit()

def update(json1_data,cur,con):
    print json1_data["id"]
    cur.execute("UPDATE Identity set id = '"+str(json1_data['id'])+"' where email = '"+json1_data['email']+"'")
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


@app.route('/admin')
def admin():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))
    if isadmin == 0:
        return redirect(url_for('login'))
    global users
    print "admin here"
    userrecords = administrator().users(con)
    users = json.loads(userrecords)
    print "users----------------------->"
    print users
    return render_template("admin.html",users=users)

@app.route("/grant_access/<string:email>/", methods=['GET'])
def grant_access(email):
    print 'before grant access email = ' + email
    sqlquery = "UPDATE Identity SET isAdmin =1 WHERE email='" + email + "'"
    print 'sql query = ' + sqlquery
    cur.execute("UPDATE Identity SET isAdmin =1 WHERE email='" + email + "'")
    con.commit()
    return redirect(url_for('admin'))

@app.route("/verify/<string:email>/", methods=['GET'])
def verify(email):
    print 'before verify access email = ' + email
    sqlquery = "UPDATE Identity SET verified =1 WHERE email='" + email + "'"
    print 'sql query = ' + sqlquery
    cur.execute(sqlquery)
    con.commit()
    return redirect(url_for('admin'))


@app.route("/delete_user/<string:email>/", methods=['GET'])
def delete_user(email):
    print 'before delete email = '+ email
    cur.execute("DELETE from Identity WHERE email='" + email + "'")
    con.commit()
    return redirect(url_for('admin'))



@google.tokengetter
def get_access_token():
    return session.get('access_token')


def main():
    setup_sql_lite_db()
    app.run()


if __name__ == '__main__':
    main()
