from flask import Blueprint, session, flash, redirect, url_for, render_template, request
from ldap3 import Connection, Server, ANONYMOUS, SIMPLE, SYNC, ASYNC, ALL, SUBTREE
from flask.ext.wtf import Form
from wtforms import TextField, SelectField, HiddenField, validators, IntegerField, PasswordField 
from wtforms_components import read_only
from wtforms.validators import Length, Required, Email

import jaydebeapi, os, json, jpype
import sqlalchemy.pool as pool

from app import app

def getconn():

	path = os.path.join(os.getcwd(),'app','jt400.jar')
	return jaydebeapi.connect('com.ibm.as400.access.AS400JDBCDriver', 'jdbc:as400://10.195.2.70;ccsid=285;translate binary=true;naming=system;prompt=false;', [session['username'],  session['password']], path,)


mypool =  pool.QueuePool(getconn, max_overflow=10, pool_size=5)


def execute_query(sql, parms = []):
	
	connection = mypool.connect()
	if not jpype.isThreadAttachedToJVM():
		jpype.attachThreadToJVM()

	cursor = connection.cursor()
	cursor.execute(sql, parms)

	return cursor


def getCurrentLibrary(firmcode):

	sql = '''SELECT envllb              
					  FROM envconfig.envlib    
					WHERE envlen = 'CNEOLIV' || '{}' 
					  AND envlap = '*BASE'     
					  AND envlsq = 10'''.format(str(firmcode))   

	result = execute_query(sql)
	library = result.fetchone()	
	return library[0]			  
	

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

	def __init__(self, user_id, forename, surname, email, group_id, role_id):
		self.user_id = user_id
		self.forename = forename
		self.surname = surname
		self.email = email
		self.group_id = group_id
		self.role_id = role_id


class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password')	


class UserForm(Form):

	user_id = TextField('User Id', validators = [validators.Length(max=10, min=1)])
	forename = TextField('Forename', validators = [validators.Length(max=30, min=1)])
	surname = TextField('Surname', validators = [validators.Length(max=50, min=1)])
	email = TextField('Email', validators = [validators.Length(max=50, min=1), validators.Email()])
	role_id = SelectField('Role', coerce=int)
	group_id = SelectField('Group', coerce=int)
	
	def __init__(self, firmcode, isNew, *args, **kwargs):
		super(UserForm, self).__init__(*args, **kwargs)	
	
		library = getCurrentLibrary(firmcode)

		results = execute_query('''SELECT DISTINCT role_id, role_description FROM {}.role'''.format(library))
		self.role_id.choices = []
		for result in results.fetchall():
			self.role_id.choices.append((int(result[0]), result[1]))

		results = execute_query('''SELECT DISTINCT group_id, group_description FROM {}.permission_user_group'''.format(library))
		self.group_id.choices = []
		for result in results.fetchall():
			self.group_id.choices.append((int(result[0]), result[1]))

		if not isNew:
			read_only(self.user_id)


#########################################################
# Methods
#########################################################
def getCustomers():

	results = execute_query("SELECT enveen FROM envconfig.envenv WHERE enveen LIKE 'CNEOLIV%' ")
	
	return results.fetchall()


def getUsers(firmcode):

	library = getCurrentLibrary(firmcode)

	sql = '''SELECT trim(u.userid), trim(u.forename), trim(u.surname), r.role_description, g.group_description, trim(p.ueeml)
					   FROM {}.user AS u
					     LEFT OUTER JOIN {}.wfusrs AS w ON u.userid = w.wfuusr
					     LEFT OUTER JOIN {}.user_role_link AS ur ON u.userid = ur.userid
					     LEFT OUTER JOIN {}.permission_role AS r ON ur.role_id = r.role_id
					     LEFT OUTER JOIN {}.user_group_link AS ug ON u.userid = ug.userid
					     LEFT OUTER JOIN {}.permission_user_group AS g ON g.group_id = ug.group_id
					     LEFT OUTER JOIN {}.person AS p ON u.percod = p.uecode
					     '''.format(library, library, library, library, library, library, library)

	results = execute_query(sql)
	
	return results.fetchall()

def getUser(firmcode, userid):

	library = getCurrentLibrary(firmcode)

	sql = '''SELECT trim(u.userid), trim(u.forename), trim(u.surname), ur.role_id, ug.group_id, trim(p.ueeml)
					   FROM {}.user AS u
					     LEFT OUTER JOIN {}.wfusrs AS w ON u.userid = w.wfuusr
					     LEFT OUTER JOIN {}.user_role_link AS ur ON u.userid = ur.userid
					     LEFT OUTER JOIN {}.user_group_link AS ug ON u.userid = ug.userid
					     LEFT OUTER JOIN {}.person AS p ON u.percod = p.uecode
					  WHERE u.userid = '{}' '''.format(library, library, library, library, library, userid)

	result = execute_query(sql)	
	result = result.fetchone()

	return User(result[0], result[1], result[2], result[5], result[4], result[3])

def updateUser(firmcode, user_id, forename, surname, group_id, role_id, email):

	library = getCurrentLibrary(firmcode)

	# Update the user
	sql = '''UPDATE {}.user
						 SET forename = trim('{}'), surname = trim('{}')
						WHERE user_id = '{}' '''.format(library, forename, surname, user_id)

	execute_query(sql)		

	# Create exactly one role e.g. the one passed in
	sql = '''DELETE FROM {}.user_role_link					 
					  WHERE user_id = '{}' 
					    AND role_id <> {}'''.format(library, user_id, role_id)
	execute_query(sql)	

	sql = '''INSERT INTO {}.user_role_link (user_id, role_id)
	           SELECT DISTINCT '{}', '{}'
	             FROM {}.user_role_link AS ur1
	               EXCEPTION JOIN {}.user_role_link AS ur2 ON ur2.user_id = '{}'
	                                                      AND ur2.role_id = '{}' '''.format(library, user_id, role_id, library, library, user_id, role_id)
	execute_query(sql)	

	# Create exactly one account access group e.g. the one passed in	                                                      
	sql = '''DELETE FROM {}.user_group_link					 
					  WHERE user_id = '{}' 
					    AND group_id <> '{}'  '''.format(library, user_id, group_id)
	execute_query(sql)	

	sql = '''INSERT INTO {}.user_group_link (user_id, group_id)
	           SELECT DISTINCT '{}', '{}'
	             FROM {}.user_group_link AS ug1
	               EXCEPTION JOIN {}.user_group_link AS ug2 ON ug2.user_id = '{}'
	                                                      AND ug2.group_id = '{}'  '''.format(library, user_id, group_id, library, library, user_id, group_id)
	execute_query(sql)	
  
	# Update the person record
	sql = '''UPDATE {}.person
						 SET ueeml = trim('{}')
						WHERE uecode = '*'||'{}' '''.format(library, email, user_id)

	execute_query(sql)	



def createUser(firmcode, user_id, forename, surname, group_id, role_id, email):

	library = getCurrentLibrary(firmcode)

	sql = '''INSERT INTO {}.user (userid, title, fornam, surnam,
                       paswrd, pasexp, mangid, failat, enabled, uecode)
             VALUES('{}', '.', '{}', '{}', 'password', '2030-01-01', '{}', 0, 'Y', '*' || '{}')'''.format(library, user_id, forename, surname, user_id, user_id)         
	execute_query(sql)		

	if role_id != 0:
		sql = '''INSERT INTO {}.user_role_link (user_id, role_id)
		           VALUES( '{}', '{}' )'''.format(library, user_id, role_id)
		execute_query(sql)		

	if group_id != 0:	
		sql = '''INSERT INTO {}.user_group_link (user_id, group_id)
		           VALUES( '{}', '{}' ) '''.format(library, user_id, group_id)
		execute_query(sql)	

	sql = '''INSERT INTO {}.wfusrs (wfuusr, wfumgr, wfuutp, wfudpt, wfualc, wfusts, wfuaus)
	          VALUES( '{}', '{}', 'IM', 'CRM', 1, 'N', '{}' )	'''.format(library, user_id, user_id, session['username'].upper())
	execute_query(sql)	      

	sql = '''INSERT INTO {}.person (uecode, ueqry, ueeml) VALUES('{}', 'Y', '{}')'''.format(library, '*' + user_id, email)
	execute_query(sql)

	addUserToLdap(user_id, forename + ' ' + surname, email)


def addUserToLdap(user_id, name, email):

	s = Server(os.environ['LDAP_HOST'], get_info=ALL)
	c = Connection(s, user='cn=root,dc=jhc,dc=net', password=os.environ['LDAP_PASSWORD'], auto_bind=True)

	attributes={'cn': user_id, 'personCode': '*' + user_id, 'sn': 'NEON', 'enabled':'TRUE', 'failCount': 0, 'firstLogin': 'TRUE', 'forgottenPasswordEnabled': 'TRUE', 'forgottenPasswordFailCount': 0, 'givenName': name, 'mail': email, 'passwordExpiry': '2199-01-01', 'passphraseExpiry': '2199-01-01', 'sessionTimeout': 0, 'uid': email, 'userPassphrase': 'AGfWPhjVcsABPwlA9aY0wUMCCKnvQST2N1kDxqoi+lukzyIE+52dgsYG694F1MkzN687+G4GOsdanwEnw/kH5OczKAdmSrYIrSvw3CxS/CI=', 'userPassword': '{SHA}cMzZAHM41tgd07YnFiG5z5qX6gA='}

	c.add('uid=' + email.strip() + ',cn=users,dc=jhc,dc=net',  ['figaroPersonV2','inetOrgPerson'], attributes)
	print(c.result)

	c.unbind()


def removeUser(firmcode, user_id):

	library = getCurrentLibrary(firmcode)

	sql = '''DELETE FROM {}.user_group_link WHERE user_id = '{}' '''.format(library, user_id)
	execute_query(sql)	

	sql = '''DELETE FROM {}.user_role_link WHERE user_id = '{}' '''.format(library, user_id)
	execute_query(sql)		

	sql = '''DELETE FROM {}.wfusrs WHERE wfuusr = '{}' '''.format(library, user_id)
	execute_query(sql)	

	sql = '''SELECT ueeml FROM {}.person WHERE uecode = '*'|| '{}' '''.format(library, user_id)
	result = execute_query(sql)	
	result = result.fetchone()
	email = result[0]	

	sql = '''DELETE FROM {}.person WHERE uecode = '*' || '{}' '''.format(library, user_id)
	execute_query(sql)	

	sql = '''DELETE FROM {}.user WHERE user_id = '{}' '''.format(library, user_id)
	execute_query(sql)	

	if email:
		removeUserFromLdap(email)



def removeUserFromLdap(email):

	s = Server(os.environ['LDAP_HOST'], get_info=ALL)
	c = Connection(s, user='cn=root,dc=jhc,dc=net', password=os.environ['LDAP_PASSWORD'], auto_bind=True)

	c.delete('uid=' + email.strip() + ',cn=users,dc=jhc,dc=net')
	print(c.result)

	c.unbind()


#########################################################
# Routes
#########################################################
@app.before_request
def before_request():

	# This redirects every request to the login page if not already logged in

	if not logged_in() and request.endpoint != 'login':
		return redirect(url_for('login'))	


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
	 
	return render_template("customer_list.html", customers=getCustomers())


@app.route('/customer/<firmcode>/')
def userList(firmcode):
	 
	return render_template("user_list.html", users=getUsers(firmcode), firmcode=firmcode)


@app.route('/customer/<firmcode>/user/<userid>', methods=['GET','POST'])
def userDetail(firmcode, userid):
	 
	user=getUser(firmcode, userid)	

	userForm = UserForm(isNew = None, firmcode=firmcode)

	if request.method == 'GET':

		userForm.user_id.data = user.user_id
		userForm.forename.data = user.forename
		userForm.surname.data = user.surname
		userForm.group_id.data = user.group_id
		userForm.role_id.data = user.role_id
		userForm.email.data = user.email

	if request.method == 'POST' and userForm.validate():
		
			updateUser(firmcode, userForm.user_id.data, userForm.forename.data, userForm.surname.data, userForm.group_id.data, userForm.role_id.data, userForm.email.data)
			flash('Updated successfully', 'alert-success')

	return render_template("user_detail.html", userForm=userForm, firmcode=firmcode)	


@app.route('/customer/<firmcode>/new', methods=['GET','POST'])
def newUser(firmcode):
	 
	userForm = UserForm(isNew = True, firmcode=firmcode)
	
	if request.method == 'POST' and userForm.validate():
		
			createUser(firmcode, userForm.user_id.data.upper(), userForm.forename.data, userForm.surname.data, userForm.group_id.data, userForm.role_id.data, userForm.email.data)
			flash('Created successfully', 'alert-success')
			return redirect(url_for('userList', firmcode=firmcode))	

	return render_template("user_detail.html", userForm=userForm, firmcode=firmcode)		


@app.route('/customer/<firmcode>/user/<user_id>/delete', methods=['POST'])
def deleteUser(firmcode, user_id):
	 
	removeUser(firmcode, user_id)

	return render_template("user_list.html", users=getUsers(firmcode), firmcode=firmcode)
