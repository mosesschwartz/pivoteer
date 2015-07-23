__author__ = 'rickcorrea'

import re
import urlparse


def isDomain(candidate):
    if not re.match("(http://)?((?!-)[A-Za-z0-9-]{1,63}(?!-)\.)+[A-Za-z]{2,}", candidate):
        return False
    else:
        return True


def grabDomain(candidate):
    if not isDomain(candidate):
        return ""
    output = candidate
    if not candidate.startswith("http://"):
        output = "http://" + output

    return output[7:].split("/")[0]


def isURL(candidate):
    o = urlparse.urlparse(candidate)

    if o.netloc != "":
        if (o.path != "") or (o.query != ""):
            return True

    return False


def isEmail(candidate):
    if not re.match("[^@]+@[^@]+\.[^@]+", candidate):
        return False
    else:
        return True


def isMD5(candidate):
    if not re.match("[a-fA-F\d]{32}", candidate):
        return False
    else:
        return True


def isIP(candidate):
    raise Exception, NotImplemented
    return True

