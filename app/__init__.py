from flask import Flask
from flask_wtf.csrf import CsrfProtect

import os

app = Flask(__name__)

if os.environ['WTF_CSRF_ENABLED'] == 'False':

	app.config['WTF_CSRF_ENABLED'] = False

else:

	app.config['WTF_CSRF_ENABLED'] = True 
	
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

app.config['JVM_PATH'] = os.environ['JVM_PATH']

from app import views