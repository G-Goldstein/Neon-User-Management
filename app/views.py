from flask import Blueprint, session, flash, redirect, url_for, render_template
from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, validators
import jaydebeapi, os, json
import sqlalchemy.pool as pool
import jpype

mod = Blueprint('base', __name__)		

class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password')	
	

@mod.route('/login', methods=['GET', 'POST'])
def login():

	form = LoginForm()
	
	if form.validate_on_submit():

		session['username'] = form.username.data
		session['password'] = form.password.data

		if logged_in():
			return redirect(url_for('userManagement.overview'))		
		
	return render_template("login.html", form=form)	
	
def connect():

	path = os.path.join(os.getcwd(),'app','jt400.jar')
	connection = jaydebeapi.connect('com.ibm.as400.access.AS400JDBCDriver', 'jdbc:as400://10.195.2.70;ccsid=285;translate binary=true;naming=system;prompt=false;libraries=CNEODTA002', [session['username'],  session['password']], path,)

	return connection

mypool =  pool.QueuePool(connect, max_overflow=10, pool_size=5)

	
def execute_query(sql, parms = []):
	
	cursor = mypool.connect()
	if not jpype.isThreadAttachedToJVM():
		jpype.attachThreadToJVM()

	cursor = connection.cursor()
	cursor.execute(sql, parms)

	return cursor
	
def logged_in():

	if 'username' not in session or 'password' not in session or session['username'] == None or session['password'] == None:
		return False

	try:
		execute_query('SELECT * FROM sysibm.sysdummy1')
	except Exception as err:
		session['username'] = None
		session['password'] = None
		flash(str(err))
		return False
	
	return True	