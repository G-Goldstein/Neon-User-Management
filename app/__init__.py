from flask import Flask
from flask_wtf.csrf import CsrfProtect

import os

app = Flask(__name__)

app.config['WTF_CSRF_ENABLED'] = os.environ['WTF_CSRF_ENABLED']
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

from app import views