from flask_wtf import Form
from wtforms import TextField
import sqlite3 as sqllite
import sys
import json

class administrator(object):
    def users(self,con):
        global cur
        cur = con.cursor()
        print cur
        # cur.execute('DROP TABLE IF EXISTS Comment')
        sql = "SELECT * FROM IDENTITY "
        print sql
        x=cur.execute(sql)
        print x
        user = cur.fetchall()
        data = []
        for u in user:
            usr={}
            usr["id"] = u[0]
            usr["email"] = u[1]
            usr["verified"] = u[2]
            usr["isadmin"] = u[3]
            data.append(usr)
        userobjs = json.dumps(data)
        print userobjs
        return userobjs





