from flask_wtf import Form
from wtforms import TextField

class SignupForm(Form):
   name = TextField("Name")
   email = TextField("Email ID")