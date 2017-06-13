from ldap3 import Connection, Server, ANONYMOUS, SIMPLE, SYNC, ASYNC, ALL, SUBTREE


s = Server('ldap://127.0.0.1:32768', get_info=ALL)
c = Connection(s, user='cn=root,dc=jhc,dc=net', password='CL!JHc2mLDt8K)', auto_bind=True)

print('Logged in as: ' + c.extend.standard.who_am_i())


c.search(search_base = 'dc=jhc,dc=net',
         search_filter = '(objectClass=*)',
         search_scope = SUBTREE)

for entry in c.response:
    print(entry['dn'], entry['attributes'])





c.unbind()
