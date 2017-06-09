
from flask import Flask

app = Flask(__name__)
app.config.from_object('config')

from app.views import mod as baseModule
app.register_blueprint(baseModule)

from app.userManagement.views import mod as userManagementModule
app.register_blueprint(userManagementModule)
