#!/bin/bash
for i in $(ls bins2); do 
	./fart.py BIN=./bins2/$i
done
