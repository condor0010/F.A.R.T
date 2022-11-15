#!/bin/python
from pwn import *
import angr, angrop, sys

binary = sys.argv[1]

