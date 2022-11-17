#!/bin/python
from pwn import *
import angr, angrop, sys
import argparse

# Argparse will replace this
binary = sys.argv[1]

# Functions for handling arguments go here

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # Add argument parsing
