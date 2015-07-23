'''
    File name: pivotEngine.py
    Author: Rick Correa
    Date created: 5/28/2015
    Python Version: 2.7
    Description: Pivoting API for various REST services for rapid intel gathering
    Copyright (c) 2015 Rick Correa

    The MIT License (MIT)

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
'''


__author__ = 'rickcorrea'

import requests
import json
import hashlib
import time
import email
import hmac

import os
import sys

import config

outputFormats = {
    "json" : "application/json",
    "xml"  : "text/xml",
    "html" : "text/html",
    "pdf"  : "application/pdf",
    "stix" : "application/stix",
    "csv"  : "text/csv",
    "snort" : "application/snort",
    "zip"  : "application/zip"
    }


def pivotOpenDns(intel, type):
    url = "https://investigate.api.opendns.com/"
    header = {}
    header["Authorization"] = "Bearer {0}".format(config.opendns_token)
    # https://investigate.opendns.com/docs/api

    # CCTLDs - listing - 1month of more
    #coming out Monday - historical data.  /
    # 503 -
    # e-mail, co-occurances, related domains, reverse ips
    #   flexible wildcard, age, alerts, pivot if someone with an @bechtel.com domain

    if type=="relatedDomains":
        url += "links/name/%s.json" %intel              # Domains around time (noisy)
    elif type=="malwareOnIP":
        url += "ips/%s/latest_domains" %intel           # IP - malware
    elif type=="simpleQuery":
        url += "security/name/%s.json" %intel           # Domain security info
    elif type=="coOccurance":
        url += "recommendations/name/%s.json" %intel    # Domain around time (noisy)
    elif type=="whois":                                 # Need to add historical emails
        url += "whois/%s" %intel                        # Domain
    elif type=="whoisEmail":
        url += "whois/emails/%s.json?limit=20" %intel   # email
    elif type=="grabDomainsOnIP":
        url += "dnsdb/ip/a/%s.json?limit=20" %intel     # IP - resource records
    #elif type=="grabDomainsOnDomain":
    #    url += "dnsdb/name/a/%s.json?limit=20" %intel   # Domains - resource records
    else:
        raise Exception, "endpoint not supported [%s]" %type
    r = requests.get(url, headers=header)

    return r.json()


def getTime():
    #return 'Tue, 27 Jan 2015 00:15:19 GMT'
    return email.utils.formatdate(time.time())


def pivotiSight(kvval, kvkey):
    API_VERSION = "2.0"

    dataSrc = "/pivot/indicator/%s/%s" %(kvkey, kvval)
    query = {}

    outFormat = outputFormats["json"]

    now = getTime()
    data = dataSrc + API_VERSION + outFormat + now
    hashed = hmac.new(config.iSight_private_key, data, hashlib.sha256)

    headers = {
        'Accept-Version' : API_VERSION,
        'Accept'         : outFormat,
        'X-Auth'         : config.iSight_public_key,
        'X-Auth-Hash'    : hashed.hexdigest(),
        'Date'           : now
    }

    print headers

    r = requests.get("https://api.isightpartners.com%s" %dataSrc, \
                    headers=headers, proxies=None, params=query)


    if r.status_code == 200:
        return r.json()
    else:
        return None


def pivotVTFile(indicator, lookupType):
    params = {}
    params["apikey"]   = config.vt_token
    vurl = "https://www.virustotal.com/vtapi/v2/file/search"

    params["query"] = "%s:%s" %(lookupType, indicator)

    # reputation url
    r  = requests.get(vurl, params=params)

    # but want https://www.virustotal.com/intelligence/search/?query=r1.fasties.org
    # Which searches the behavior that makes DNS requests to r1.fasties.org

    return r.json()


def queryVT(indicator, lookupType):
    params = {}
    r = None

    params["apikey"]   = config.vt_token
    params["allinfo"]  = 1
    vurl = "https://www.virustotal.com/vtapi/v2/%s/report" %lookupType

    if lookupType == "domain":
        params["domain"] = indicator
    elif lookupType == "ip-address":
        params["ip"] = indicator
    else:
        params["resource"] = indicator

    #params["resource"] = indicator

    # reputation url
    r  = requests.get(vurl, params=params)

    # but want https://www.virustotal.com/intelligence/search/?query=r1.fasties.org
    # Which searches the behavior that makes DNS requests to r1.fasties.org

    #print r.text, r.status_code, r.url

    return r.json()


def walkJson(jobj):
    jobj = dict()
    jobjElements = []
    jobjKeys = jobj.keys()
    while(len(jobjKeys) != 0):
        for i in jobjKeys():
            print i, jobjKeys(i)
            if type(jobjKeys(i)) == dict:
                walkJson(jobjKeys[i])

            else:
                jobjElements.append(jobjKeys[i])
    return jobjElements


if __name__ == "__main__":
    print json.dumps(pivotOpenDns("utep.edu", "whois"), indent=3)
