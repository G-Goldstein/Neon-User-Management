from flask import Flask
from flask_wtf.csrf import CsrfProtect

app = Flask(__name__)

app.config['WTF_CSRF_CHECK_DEFAULT'] = False

from app import views