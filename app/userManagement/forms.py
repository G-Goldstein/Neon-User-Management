from flask.ext.wtf import Form
from wtforms import TextField, SelectField, HiddenField, validators, IntegerField
from wtforms_components import read_only
from wtforms.validators import Length, Required

from app.views import execute_query

class Table(Form):

	formName        = HiddenField('Form Name', default='Table')
	type            = SelectField('Type', validators = [validators.Length(min=1, message="This field is required")])
	includeInCopy   = SelectField('Include In Copy', 
								  validators = [validators.Length(min=1, message="This field is required")], 
								  choices=[("",""), ("A", "ALL"), ("S", "SOME"), ("N", "NONE")])
	defunct         = SelectField('Defunct', 
								   validators = [validators.Length(min=1, message="This field is required")], 
								   choices=[("",""), ("Y", "Y"), ("N", "N")], default="N")
	extractTableNotes = TextField('Table Notes', validators = [validators.Length(max=1000)])
	
	def __init__(self, *args, **kwargs):
		super(Table, self).__init__(*args, **kwargs)	
	
		results = execute_query('''SELECT DISTINCT type_code, type_description, default_include_in_copy
									FROM figaro_table_type AS t2''')
		self.type.choices = [("","")]
		
		for result in results.fetchall():
			self.type.choices.append((result.type_code, result.type_description))
	