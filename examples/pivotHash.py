from pivoteer import Hopper
from pivoteer import pivotHash
from pivoteer import pivotIP
from pivoteer import pivotDomain
from pivoteer import pivotEmail

bigResult = pivotHash("514d6edce7be091c45a52fcdddc47f0e279cddee50573c0dfdd2ae08c116c7ed")

print "initial\n", bigResult

# double pivot
emailPivot = Hopper()
for email in bigResult.email_container.keys():
    emailPivot = pivotEmail(email)
bigResult += emailPivot
print "initial + email pivot\n", bigResult

#triple pivot
domainPivot = Hopper()
for domain in bigResult.domain_container.keys():
    domainPivot = pivotDomain(domain)
bigResult += domainPivot

print "add another domain route\n", bigResult
