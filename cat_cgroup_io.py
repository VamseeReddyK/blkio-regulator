#!/usr/bin/env python
from __future__ import with_statement
import socket
import os
import struct
import functools
import sys
from os import listdir
from os.path import isfile, join
import commands
from time import sleep
from sets import Set
from multiprocessing import Process


def catcgroupIO():

	items=[]
	itemshd=[]
#	childstr = commands.getoutput("find /sys/fs/cgroup/blkio/  -maxdepth 1 -name user_* -type d ")
#	print("children is " + childstr)
#	children = childstr.strip().split('\n')
	i = 1
	for i in range (1, 6):
		pathname = "/sys/fs/cgroup/blkio/user_"+str(i)+"/blkio.io_serviced";
		if  os.path.exists(pathname):
		#	print pathname
			iostr = commands.getoutput("cat "+pathname)
			iolines = iostr.split("\n")
			for line in iolines:
				if "8:16 Read" in line:
					words = line.split()
					items.append(int(words[2]))
				if "8:0 Read" in line:
					words = line.split()
					itemshd.append(int(words[2]))
	return items,itemshd
	
def main():
    # FIXME: Hardcoded structs are not portable
	pass

if __name__ == "__main__":
	items,itmeshd = catcgroupIO()
	print "ssd:"
	print items
	print "hd:"
	print itmeshd
