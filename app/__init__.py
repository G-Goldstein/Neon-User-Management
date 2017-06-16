from flask import Flask

app = Flask(__name__)
app.config['CSRF_ENABLED'] = True

app.config['SECRET_KEY'] = 'you-will-never-guess-JOBS5!'
app.config['REMEMBER_COOKIE_DURATION'] = 604800



from app import views