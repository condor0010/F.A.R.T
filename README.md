## Overview
```
   ad88                                
  d8"                           ,d     
  88                            88     
MM88MMM ,adPPYYba, 8b,dPPYba, MM88MMM  
  88    ""     `Y8 88P'   "Y8   88     
  88    ,adPPPPP88 88           88     
  88    88,    ,88 88           88,    
  88    `"8bbdP"Y8 88           "Y888
  
  Format And ROP Toolkit 💨 

```
FART is a tool developed by Hannah Callihan, Joshua Connolly, Louis Orcinolo, and Warren Smith for the purpose of Automatic Exploit Generation. When given a binary or folder of binaries, FART is able to extract the flag or flags contained in flag.txt.

## Dependencies
Your machine must have the following tools and their dependencies before you can run FART:
- [angr](https://angr.io/)
- [angrop](https://github.com/angr/angrop)
- [pwntools](https://docs.pwntools.com/en/stable/)
- [r2pipe](https://www.radare.org/n/r2pipe.html)

## Installation and Usage
```
git clone https://github.com/condor0010/AutoExploit.git
cd AutoExploit
```
- Display the help message and exit: `./fart.py -h, --help`
- Exploit a single binary: `./fart.py -b, --binary <file path of binary>`
- Exploit all binaries in a directory: `./fart.py -d, --directory <file path to folder with binaries>`
- Set the print verbosity level from 0-4: `./fart.py -v, --verbosity <value from 0-4>`
