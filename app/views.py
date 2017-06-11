from flask import Blueprint, session, flash, redirect, url_for, render_template
from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, validators
import jaydebeapi, os, json

from app import app

class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password')	
	
def execute_query(sql, parms = []):
	
	path = os.path.join(os.getcwd(),'app','jt400.jar')
	connection = jaydebeapi.connect('com.ibm.as400.access.AS400JDBCDriver', 'jdbc:as400://10.195.2.70;ccsid=285;translate binary=true;naming=system;prompt=false;', [session['username'],  session['password']], path,)

	cursor = connection.cursor()
	cursor.execute(sql, parms)

	return cursor

def getCurrentLibrary(firmcode):

	sql = '''SELECT envllb              
					  FROM envconfig.envlib    
					WHERE envlen = 'CNEOLIV' || {} 
					  AND envlap = '*BASE'     
					  AND envlsq = 10'''.format("'" + str(firmcode) + "'")   

	result = execute_query(sql)
	return result.fetchone()				  
	
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

#########################################################
# Classes
#########################################################
class User:

	def __init__(self):
		self.username = None
		self.forename = None
		self.surname = None



#########################################################
# Methods
#########################################################
def getCustomers():

	sql = '''SELECT enveen FROM envconfig.envenv WHERE enveen LIKE 'CNEOLIV%' '''

	results = execute_query(sql)
	
	return results.fetchall()


def getUsers(firmcode):

	library = getCurrentLibrary(firmcode)
	library = library[0]

	sql = 'SELECT userid, forename, surname FROM ' + library.strip() + '.user'

	results = execute_query(sql)
	
	return results.fetchall()

def getUser(firmcode, userid):

	library = getCurrentLibrary(firmcode)
	library = library[0]

	sql = 'SELECT userid, forename, surname FROM ' + library.strip() + '.user'

	result = execute_query(sql)	
	result = result.fetchone()

	user = User()
	user.userid = result[0]
	user.forename = result[1]
	user.surname = result[2]
	
	return user


#########################################################
# Routes
#########################################################
@app.route('/login', methods=['GET', 'POST'])
def login():

	form = LoginForm()
	
	if form.validate_on_submit():

		session['username'] = form.username.data
		session['password'] = form.password.data

		if logged_in():
			return redirect(url_for('customerList'))		
		
	return render_template("login.html", form=form)	


@app.route('/customer/')
def customerList():
	 
	if not logged_in():
		return redirect(url_for('login'))	
	 
	return render_template("customer_list.html", customers=getCustomers())



@app.route('/customer/<firmcode>/')
def userList(firmcode):
	 
	if not logged_in():
		return redirect(url_for('login'))	
	 
	return render_template("user_list.html", users=getUsers(firmcode), firmcode=firmcode)


@app.route('/customer/<firmcode>/<userid>')
def userDetail(firmcode, userid):
	 
	if not logged_in():
		return redirect(url_for('login'))	
	 
	return render_template("user_detail.html", user=getUser(firmcode, userid), firmcode=firmcode)	