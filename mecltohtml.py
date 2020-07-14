#!/usr/bin/env python

import re

filein = open("aText.mecl","r",encoding="utf-16")
fileout = open("aText.html","w")

pre = """<html><head><meta charset="UTF-8"/></head><body>"""
suf = """</body></html>"""

fileout.write(pre)

dup = re.compile(' (?P<attrib>\w+)="\S+" (?P=attrib)="\S+"')
strip = re.compile('<(J|G|SP|BKGR) [^>]+>')
strip2 = re.compile('<HSRT>[^<]*</HSRT>')
ruby_char = re.compile("JRUBY")
for line in filein:
    # remove fancy tags
    line = dup.sub(" ",line)
    line = strip.sub("",line)
    line = strip2.sub("",line)
    # fix furigana
    line = ruby_char.sub("ruby",line)

    fileout.write(line)

fileout.write(suf)

filein.close()
fileout.close()
