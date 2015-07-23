'''
    File name: pivoteer.py
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

import pivotEngine
import collections


class Hopper(object):
    def __init__(self):
        self.hash_container = collections.defaultdict(list)
        self.domain_container = collections.defaultdict(list)
        self.url_container = collections.defaultdict(list)
        self.ip_container = collections.defaultdict(list)
        self.email_container = collections.defaultdict(list)
        self.import_table_container = collections.defaultdict(list)
        self.section_hash_container = collections.defaultdict(list)


    def __str__(self):
        output = ""
        output += "%s\n" %self.hash_container.keys()
        output += "%s\n" %self.domain_container.keys()
        output += "%s\n" %self.url_container.keys()
        output += "%s\n" %self.ip_container.keys()
        output += "%s\n" %self.email_container.keys()
        output += "%s\n" %self.import_table_container.keys()
        output += "%s\n" %self.section_hash_container.keys()
        return output


    def __add__(self, other):
        output = Hopper()

        if self == None:
            if other == None:
                return None
            else:
                return other

        if type(other) != Hopper:
            raise Exception, "Only Hopper Instances allowed to be added.  Got: [%s]" %type(other)

        temp = self.hash_container.copy()
        temp.update(other.hash_container)
        output.hash_container = temp

        temp = self.domain_container.copy()
        temp.update(other.domain_container)
        output.domain_container = temp

        temp = self.url_container.copy()
        temp.update(other.url_container)
        output.url_container = temp

        temp = self.ip_container.copy()
        temp.update(other.ip_container)
        output.ip_container = temp

        temp = self.email_container.copy()
        temp.update(other.email_container)
        output.email_container = temp

        temp = self.domain_container.copy()
        temp.update(other.domain_container)
        output.domain_container = temp

        temp = self.import_table_container.copy()
        temp.update(other.import_table_container)
        output.import_table_container = temp

        temp = self.section_hash_container.copy()
        temp.update(other.section_hash_container)
        output.section_hash_container = temp

        return output


def parseVTIP(dump):
    h = Hopper()

    if dump["response_code"] == 0:
        return h
    samples = dump["detected_downloaded_samples"]
    for sample in samples:
        h.hash_container[sample["sha256"]].append("VT")
    samples = dump["detected_urls"]
    for sample in samples:
        h.url_container[sample["url"]].append("VT")
    samples = dump["resolutions"]
    for sample in samples:
        h.domain_container[sample["hostname"]].append("VT")
    samples = dump["detected_communicating_samples"]
    for sample in samples:
        h.hash_container[sample["sha256"]].append("VT")

    return h


def parseVTDomain(dump):
    h = Hopper()

    if dump["response_code"] == -1:
        return h

    if dump["verbose_msg"] == "Domain not found in dataset":
        return h

    if dump.has_key("resolutions"):
        resolutions = dump["resolutions"]
        for res in resolutions:
            h.ip_container[res["ip_address"]].append("VT Domain")
    if dump.has_key("detected_urls"):
        detected_urls = dump["detected_urls"]
        for res in detected_urls:
            h.url_container[res["url"]].append("VT Domain")
    if dump.has_key("domain_siblings"):  # TODO: Test, not sure if this works since it's not well documented in VT
        dSiblings = dump["domain_siblings"]
        for sibling in dSiblings:
            h.domain_container[sibling].append("VT Sibling Domain")
    if dump.has_key("subdomains"):
        subdomains = dump["subdomains"]
        for subd in subdomains:
            h.domain_container[subd].append("VT Subdomains")

    return h


# fullScan = True does a pivot search on section and import hashes, both are slow and expensive and have a different
#  daily limit (50k)
def parseVTFile(dump, fullScan = False):
    h = Hopper()

    if dump["response_code"] == 0:
        return h


    add_info = dump["additional_info"]

    impTblHash = add_info["pe-imphash"]

    if fullScan == True:
        out = pivotEngine.pivotVTFile(impTblHash, "imphash")
        relatedHashes = __parseVTHashes(out)
        if relatedHashes != None:
            for entry in relatedHashes:
                h.import_table_container[entry].append("VT-import-table")

    behavior = add_info["behaviour-v1"]
    net = behavior["network"]
    udp = net["udp"]
    tcp = net["tcp"]
    dns = net["dns"]
    http = net["http"]

    for i in udp:
        base = i.split(":")[0]
        if base == u"<MACHINE_DNS_SERVER>":
            continue
        h.ip_container[base].append("VT-behavior")
    for i in tcp:
        base = i.split(":")[0]
        h.ip_container[base].append("VT-behavior")
    for i in dns:
        h.ip_container[i["ip"]].append("VT-behavior")
        h.domain_container[i["hostname"]].append("VT-behavior")
    for i in http:
        h.url_container[i["url"]].append("VT-behavior")

    # full scans are a really expensive VT operation.  Make it optional
    if fullScan == True:
        sections = add_info["sections"]
        for i in sections:
            sname = i[0]
            shash = i[5]

            out = pivotEngine.pivotVTFile(shash, "sectionmd5")
            relatedHashes = __parseVTHashes__(out)
            if relatedHashes == None:
                continue
            for entry in relatedHashes:
                h.section_hash_container[entry].append("VT-section-%s" %sname)

    h.hash_container[dump["md5"]].append("VT-Hash")

    return h


def __parseVTHashes__(dump):
    if dump["response_code"] == 0:
        return
    else:
        return dump["hashes"]


def parseOpenDNSWhoIs(results):
    h = Hopper()

    if results.has_key("errorMessage"):
        if results["errorMessage"] == "Not found":
            return h
    if results.has_key("administrativeContactEmail"):
        aemail = results["administrativeContactEmail"]
        h.email_container[aemail].append("OpenDNS-AdminEmail")
    if results.has_key("technicalContactEmail"):
        temail = results["technicalContactEmail"]
        h.email_container[temail].append("OpenDNS-TechEmail")
    if results.has_key("registrantEmail"):
        remail = results["registrantEmail"]
        h.email_container[remail].append("OpenDNS-RegEmail")

    for email in results["emails"]:
        h.email_container[email].append("OpenDNS-GenEmail")

    return h


def parseOpenDNSRelDoms(results):
    h = Hopper()
    if len(results) == 0:
        return h

    if results["found"] == True:
        for dom, thresh in results["tb1"]:
            # TODO: Check threshold
            h.domain_container[dom].append("OpenDNS-RelatedDomains")
    return h


def parseOpenDNSCoOccurance(results):
    h = Hopper()
    if len(results) == 0:
        return h

    if results["found"] == True:
        for dom, scores in results["pfs2"]:
            # TODO: Check scores
            h.domain_container[dom].append("OpenDNS-RelatedDomains")
    return h


def parseOpenDNSARecords(results):
    h = Hopper()

    for i in results["rrs"]:
        dom = i["rr"]
        if dom.endswith("."):
            dom=dom[:-1]
        h.domain_container[dom].append("OpenDNS-ARecordsOnIP")
    return h


def parseOpenDNSMalOnIP(results):
    h = Hopper()

    for i in results:
        dom = i["name"]
        if dom.endswith("."):
            dom=dom[:-1]
        h.domain_container[dom].append("OpenDNS-MalOnIP")
    return h


def parseOpenDNSEmail(results):
    h = Hopper()

    emails = results.keys()

    for email in emails:
        entry = results[email]
        doms = entry["domains"]

        for domEntry in doms:
            domain = domEntry["domain"]
            h.domain_container[domain].append("OpenDNS-DNSEmail")

    return h


def pivotIP(ipAddr):
    h1 = parseVTIP(pivotEngine.queryVT(ipAddr, "ip-address"))
    h2 =  parseOpenDNSARecords(pivotEngine.pivotOpenDns(ipAddr, "grabDomainsOnIP"))
    h3 =  parseOpenDNSARecords(pivotEngine.pivotOpenDns(ipAddr, "malwareOnIP"))

    return h1 + h2 + h3


def pivotDomain(domain):
    h1 = parseVTDomain(pivotEngine.queryVT(domain, "domain"))
    h2 = parseOpenDNSWhoIs(pivotEngine.pivotOpenDns(domain, "whois"))
    h3 = parseOpenDNSRelDoms(pivotEngine.pivotOpenDns(domain, "relatedDomains"))
    h4 = parseOpenDNSCoOccurance(pivotEngine.pivotOpenDns(domain, "coOccurance"))

    return h1 + h2 + h3 + h4


def pivotHash(hash):
    h1 = parseVTFile(pivotEngine.queryVT(hash, "file"))
    return h1


def pivotEmail(email):
    h1 = parseOpenDNSEmail(pivotEngine.pivotOpenDns(email, "whoisEmail"))
    return h1








