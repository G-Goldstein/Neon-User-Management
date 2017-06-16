from flask import Flask

app = Flask(__name__)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

app.config['SECRET_KEY'] = 'you-will-never-guess-JOBS5!'
app.config['REMEMBER_COOKIE_DURATION'] = 604800



from app import views