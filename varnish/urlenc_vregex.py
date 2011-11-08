#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Eduardo S. Scarpellini, <scarpellini@gmail.com>

from sys import argv

print "".join(["(%s|%s|%s)" % (c, str(hex(ord(c.upper()))).replace("0x", "%", 1).upper(), str(hex(ord(c.lower()))).replace("0x", "%", 1).upper()) for c in str(argv[1])])
