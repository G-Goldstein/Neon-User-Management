from app.views import execute_query
from itertools import groupby

LIBRARY = 'CNEODTA002'

def getUsers():

	sql = 'SELECT userid FROM ' + LIBRARY + '.user'

	results = execute_query(sql)
	
	return results.fetchall()

