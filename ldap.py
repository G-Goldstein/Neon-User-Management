from ldap3 import Connection, Server, ANONYMOUS, SIMPLE, SYNC, ASYNC, ALL, SUBTREE, ALL_ATTRIBUTES


s = Server('ldap://127.0.0.1:32768', get_info=ALL)
c = Connection(s, user='cn=root,dc=jhc,dc=net', password='CL!JHc2mLDt8K)', auto_bind=True)

print('Logged in as: ' + c.extend.standard.who_am_i())



attributes={'o': 'JHC.net', 'description': 'Root domain for JHC.Net LDAP entries'}
c.add('dc=jhc,dc=net',  ['organization','dcObject'], attributes)
print(c.result)


attributes={'description': 'Groups container'}
c.add('cn=groups,dc=jhc,dc=net',  ['container',], attributes)
print(c.result)


attributes={'description': 'Cloud Neon'}
c.add('cn=neon,cn=groups,dc=jhc,dc=net',  ['top', 'container',], attributes)
print(c.result)


attributes={'description': 'Investment Manager Group', 'uniqueMember': 'cn=dummy,dc=jhc,dc=net'}
c.add('cn=im-grp,cn=neon,cn=groups,dc=jhc,dc=net',  ['figaroGroupV2', 'top'], attributes)
print(c.result)


attributes={'description': 'Compliance Officer Group', 'uniqueMember': 'cn=dummy,dc=jhc,dc=net'}
c.add('cn=co-grp,cn=neon,cn=groups,dc=jhc,dc=net',  ['figaroGroupV2', 'top'], attributes)
print(c.result)


attributes={'description': 'Users container'}
c.add('cn=users,dc=jhc,dc=net',  ['container', ], attributes)
print(c.result)



c.search(search_base = 'dc=jhc,dc=net',
         search_filter = '(cn=RAISONA)',
         search_scope = SUBTREE,
         attributes=ALL_ATTRIBUTES)

for entry in c.response:
	print(entry['dn'], entry['attributes']['enabled'], entry['attributes']['userPassphrase'], entry['attributes']['userPassword'])





c.unbind()
