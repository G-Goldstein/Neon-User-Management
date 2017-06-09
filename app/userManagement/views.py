from flask import Blueprint, render_template, request, url_for, redirect, flash
from urllib import parse

from app.views import execute_query, logged_in
from app.userManagement.forms import *
from app.userManagement.api import *

mod = Blueprint('userManagement', __name__, url_prefix='/userManagement')

@mod.route('/')
def overview():
	 
	if not logged_in():
		return redirect(url_for('base.login'))	
	 
	return render_template("userManagement/list.html", users=getUsers())