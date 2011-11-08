#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Eduardo S. Scarpellini, <scarpellini@gmail.com>

import sys
import re

input = str(sys.argv[1]).upper()
output = ""

#if not re.search(r'[a-z0-9]+', input, re.IGNORECASE):
#    print "Expected an alphanumeric string as input"
#    sys.exit(1)


#print "URL ENCODE> %s: %s" % (input, "".join(["(%s|%s|%s)" % (str(c).upper(), str(hex(ord(c.upper()))).replace("0x", "%", 1).upper(), str(hex(ord(c.lower()))).replace("0x", "%", 1).upper()) for c in str(input)]))


for i_chr in input:
    if re.match(r'[a-z]', i_chr, re.IGNORECASE):
        i_ascii_hxint = str(hex(ord(i_chr))).replace("0x", "", 1)

        output += "(%s|%%[%s%s]%s)" % (i_chr, i_ascii_hxint[0], int(i_ascii_hxint[0]) + 2, i_ascii_hxint[1].upper())

    else:
        output += "(%s|%s)" % (i_chr, str(hex(ord(i_chr))).replace("0x", "%", 1).upper())

print "URLENCODE \"%s\": %s" % (input, output)
