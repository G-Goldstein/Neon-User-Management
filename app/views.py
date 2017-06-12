from flask import Blueprint, session, flash, redirect, url_for, render_template, request

import jaydebeapi, os, json

from flask.ext.wtf import Form
from wtforms import TextField, SelectField, HiddenField, validators, IntegerField, PasswordField 
from wtforms_components import read_only
from wtforms.validators import Length, Required

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
		self.userid = None
		self.forename = None
		self.surname = None
		self.isInWorkflow = None
		self.group = None
		self.role = None


class UserForm(Form):

	user_id = TextField('user Id')
	forename = TextField('Forename')
	surname = TextField('Surname')
	role_id = SelectField('Role', coerce=int)
	group_id = SelectField('Group', coerce=int)
	
	def __init__(self, firmcode, *args, **kwargs):
		super(UserForm, self).__init__(*args, **kwargs)	
	
		library = getCurrentLibrary(firmcode)
		library = library[0]

		results = execute_query('''SELECT DISTINCT role_id, role_description FROM {}.role'''.format(library))
		self.role_id.choices = [(0,"")]
		for result in results.fetchall():
			self.role_id.choices.append((int(result[0]), result[1]))

		results = execute_query('''SELECT DISTINCT group_id, group_description FROM {}.permission_user_group'''.format(library))
		self.group_id.choices = [(0,"")]
		for result in results.fetchall():
			self.group_id.choices.append((int(result[0]), result[1]))

		read_only(self.user_id)


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

	sql = 'SELECT trim(userid), forename, surname FROM ' + library.strip() + '.user'

	results = execute_query(sql)
	
	return results.fetchall()

def getUser(firmcode, userid):

	library = getCurrentLibrary(firmcode)
	library = library[0]

	sql = '''SELECT trim(u.userid), trim(u.forename), trim(u.surname), trim(w.wfuusr), ur.role_id, ug.group_id
					   FROM {}.user AS u
					     LEFT OUTER JOIN {}.wfusrs AS w ON u.userid = w.wfuusr
					     LEFT OUTER JOIN {}.user_role_link AS ur ON u.userid = ur.userid
					     LEFT OUTER JOIN {}.user_group_link AS ug ON u.userid = ug.userid
					  WHERE u.userid = '{}' 
					  '''.format(library, library, library, library, userid)

	result = execute_query(sql)	
	result = result.fetchone()

	user = User()
	user.user_id = result[0]
	user.forename = result[1]
	user.surname = result[2]
	user.isInWorkflow = result[3]
	user.group_id = result[5]
	user.role_id = result[4]


	return user

def updateUser(firmcode, user_id, forename, surname, group_id, role_id):

	library = getCurrentLibrary(firmcode)
	library = library[0]

	sql = '''UPDATE {}.user
						 SET forename = trim('{}'), surname = trim('{}')
						WHERE user_id = '{}' '''.format(library, forename, surname, user_id)

	execute_query(sql)		

	if role_id == 0:

		sql = '''DELETE FROM {}.user_role_link					 
						  WHERE user_id = '{}' '''.format(library, user_id)
		execute_query(sql)					 

	else:

		sql = '''INSERT INTO {}.user_role_link (user_id, role_id)
		           SELECT DISTINCT '{}', '{}'
		             FROM {}.user_role_link AS ur1
		               EXCEPTION JOIN {}.user_role_link AS ur2 ON ur2.user_id = '{}'
		                                                      AND ur2.role_id = '{}' '''.format(library, user_id, role_id, library, library, user_id, role_id)
		execute_query(sql)	

		sql = '''DELETE FROM {}.user_role_link					 
						  WHERE user_id = '{}' 
						    AND role_id <> {}'''.format(library, user_id, role_id)
		execute_query(sql)			                                                      


	if group_id ==0:

		sql = '''DELETE FROM {}.user_group_link					 
						  WHERE user_id = '{}' '''.format(library, user_id)
		execute_query(sql)					  

	else:

		sql = '''INSERT INTO {}.user_group_link (user_id, group_id)
		           SELECT DISTINCT '{}', '{}'
		             FROM {}.user_group_link AS ug1
		               EXCEPTION JOIN {}.user_group_link AS ug2 ON ug2.user_id = '{}'
		                                                      AND ug2.group_id = '{}'  '''.format(library, user_id, group_id, library, library, user_id, group_id)
		execute_query(sql)	

		sql = '''DELETE FROM {}.user_group_link					 
						  WHERE user_id = '{}' 
						    AND group_id <> '{}'  '''.format(library, user_id, group_id)
		execute_query(sql)	


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


@app.route('/customer/<firmcode>/<userid>', methods=['GET','POST'])
def userDetail(firmcode, userid):
	 
	if not logged_in():
		return redirect(url_for('login'))	

	user=getUser(firmcode, userid)	

	userForm = UserForm(firmcode=firmcode)


	if request.method == 'POST':
	
		if userForm.validate():
		
			updateUser(firmcode, userForm.user_id.data, userForm.forename.data, userForm.surname.data, userForm.group_id.data, userForm.role_id.data)
			flash('Updated successfully', 'alert-success')

	else:

		userForm.user_id.data = user.user_id
		userForm.forename.data = user.forename
		userForm.surname.data = user.surname
		userForm.group_id.data = user.group_id
		userForm.role_id.data = user.role_id




	 
	return render_template("user_detail.html", userForm=userForm, firmcode=firmcode)	