from flask import Flask
from flask_wtf.csrf import CsrfProtect

app = Flask(__name__)

app.secret_key = 'you-will-never-guess-JOBS5!'

CsrfProtect(app)

from app import views