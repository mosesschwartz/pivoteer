Pivoteer is an API for various REST services for rapid intel gathering and pivoting.


# Installation
```bash
virtualenv venv
source venv/bin/activate

python setup.py install 
```

## Build a config file in your working directory.  
```python
Create a config file in your local working directory and have
# NEW KEY
iSight_public_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
iSight_private_key = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
vt_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
opendns_token = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX"
```
with the appropriate keys


# Examples
There are a few examples in the examples directory
```bash
(venv)Anon:examples rickcorrea$ python pivotHash.py
initial
[u'5cc3acd8532f40ee8839d6858769ddec']
[u'www.cr0798.com', u'dlq.tao8web.com']
[u'http://www.cr0798.com/haoy.ini', u'http://www.cr0798.com/gg.htm', u'http://www.cr0798.com/hawg.ini']
[u'222.186.58.37', u'222.186.50.217', u'23.102.23.44']
[]
[]
[]

initial + email pivot
[u'5cc3acd8532f40ee8839d6858769ddec']
[u'www.cr0798.com', u'dlq.tao8web.com']
[u'http://www.cr0798.com/haoy.ini', u'http://www.cr0798.com/gg.htm', u'http://www.cr0798.com/hawg.ini']
[u'222.186.58.37', u'222.186.50.217', u'23.102.23.44']
[]
[]
[]

add another domain route
[u'5cc3acd8532f40ee8839d6858769ddec']
[u'www.cr0798.com', u'dlq.tao8web.com']
[u'http://www.cr0798.com/haoy.ini', u'http://www.cr0798.com/gg.htm', u'http://www.cr0798.com/hawg.ini']
[u'222.186.58.37', u'222.186.50.217', u'23.102.23.44']
[u'308524715@qq.com']
[]
[]
```

# Write your own
```python
# import the functions
from pivoteer import Hopper
from pivoteer import pivotHash
from pivoteer import pivotIP
from pivoteer import pivotDomain
from pivoteer import pivotEmail
# don't forget to include your config.py file in your working directory

# do an initial pivot off a domain
bigResult = pivotHash("514d6edce7be091c45a52fcdddc47f0e279cddee50573c0dfdd2ae08c116c7ed")

print "initial\n", bigResult

# double pivot
emailPivot = Hopper()
for email in bigResult.email_container.keys():
    emailPivot = pivotEmail(email)
bigResult += emailPivot
print "initial + email pivot\n", bigResult

# triple pivot
domainPivot = Hopper()
for domain in bigResult.domain_container.keys():
    domainPivot = pivotDomain(domain)
bigResult += domainPivot

print "add another domain route\n", bigResult
```

# ToDo
* Gracefully exit when a particular API key doesn't exist (e.g. if a user doesn't have an iSight account)
* Do non-blocking IO (grequests)
* Add more service pivoting services
* Allow a user to enter their tolerance for False Positives (i.e exclude related domains)
