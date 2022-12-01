#!/bin/python
from pwn import *
import angr, angrop, sys
import argparse

# Functions for handling arguments go here

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='An Automatic Exploit Generation tool created by Hannah Callihan, Joshua Connolly, Louis Orcinolo, and Warren Smith')
    parser.add_argument('-f', '--file', type=str, required=True, help='name of binary you want to exploit')

    args = parser.parse_args()

    binary = args.file
