#!/bin/bash
rm .flags.pot
rm -rf ./core_files/*
clear
python fart.py -d new_bins/$1  2>/dev/null
