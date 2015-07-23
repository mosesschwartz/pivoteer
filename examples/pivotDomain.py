# add .. to path in case we're being run from the examples directory
# and pivoteer isn't in our path
import sys, os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../')

from pivoteer import Hopper
from pivoteer import pivotHash
from pivoteer import pivotIP
from pivoteer import pivotDomain
from pivoteer import pivotEmail

bigResult = pivotDomain("www.opendns.com")

print "initial\n", bigResult

# double pivot
emailPivot = Hopper()
for email in bigResult.email_container.keys():
    emailPivot = pivotEmail(email)
bigResult += emailPivot
print "initial + email pivot\n", bigResult


print "add another domain route\n", bigResult
