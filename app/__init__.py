from flask import Flask
from flask_wtf.csrf import CsrfProtect

app = Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = False
app.config['SECRET_KEY'] = 'My silly secret key'

from app import views