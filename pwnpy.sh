export PROJECT_HOME=$HOME/Devel
#export VIRTUAL_ENV_DISABLE_PROMPT=1
source /usr/local/bin/virtualenvwrapper.sh
mkvirtualenv --python=$(which python3) angr && python3 -m pip install angr pwntools angr-management autopep8 capstone colorama cython keystone-engine pefile qiling rzpipe ropgadget ropper sudo unicorn z3-solver tabulate angrop progressbar r2pipe --upgrade
