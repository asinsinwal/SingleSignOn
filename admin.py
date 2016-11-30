from flask_wtf import Form
from wtforms import TextField
import sqlite3 as sqllite
import sys

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
        users = cur.fetchall()
        print users
        return users



