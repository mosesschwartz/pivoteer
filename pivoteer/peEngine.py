'''
    File name: peEngine.py
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

#pefile==1.2.10-139
import pefile
import os
import sys
import pivotEngine
import ordlookup


class REFile:
    def __init__(self, file):
        self.pe = None
        self.filename = file
        self.sectionHashes = {}
        self.impHash = ""
        self.populate()

    def getSize(self):
        self.size = os.stat(self.filename).st_size

    def populate(self):
        self.getSize()
        self.pe = pefile.PE(self.filename, fast_load=True)

        impTable = self.pe.get_imphash()

        for section in self.pe.sections:
            #print section.Name,
            #print section.VirtualAddress,
            #print section.SizeOfRawData,
            #print section.Misc_VirtualSize,
            #print section.get_hash_md5()
            self.sectionHashes["%s@%s" %(section.Name, section.VirtualAddress)] = section.get_hash_md5()

        impstrs = []
        if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress != 0:
            self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    libname = entry.dll.lower()
                    parts = libname.rsplit('.', 1)
                    for imp in entry.imports:
                        funcname = None
                        if not imp.name:
                            funcname = ordlookup.ordLookup(entry.dll.lower(), imp.ordinal, make_name=True)
                            if not funcname:
                                raise Exception("Unable to look up ordinal %s:%04x" % (entry.dll, imp.ordinal))
                        else:
                            funcname = imp.name

                        if not funcname:
                            continue

                        impstrs.append('%s.%s' % (libname.lower(),funcname.lower()))

        self.impHash = self.pe.get_imphash()
        if self.impHash == None:
            self.impHash = ""


    def __str__(self):
        out = ""
        out += "FileName:   %s\n" %self.filename
        out += "    Size:   %d\n" %self.size
        out += " ImpHash:   %s\n" %self.impHash

        for (k,v) in self.sectionHashes.items():
            out+= "   %s: %s\n" %(k,v)

        return out


    def everything(self):
        return self.pe.dump_info()


if __name__ == "__main__":
    sample = sys.argv[1]

    ref = REFile(sample)

    print "Searching imgHash", ref.impHash, "\nand sectionHash", ref.sectionHashes

    jsonResp = pivotEngine.pivotVTFile(ref.impHash, "imphash")

    if jsonResp["response_code"] == 1:
        print "   Related Samples[IMP]:", jsonResp["hashes"]

    for i in ref.sectionHashes:
        sectionHash = ref.sectionHashes[i]
        jsonResp = pivotEngine.pivotVTFile(sectionHash, "sectionmd5")
        if jsonResp["response_code"] == 1:
            print "   Related Samples[SEC]:", jsonResp["hashes"]

