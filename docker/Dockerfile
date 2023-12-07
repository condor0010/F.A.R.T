RUN apt-get update -y -qq
RUN apt-get install -y -qq  
    systemd-coredump  
    g++  
    gcc  
    gcc-multilib  
    gdb  
    gdb-multiarch  
    git  
    locales  
    make  
    man  
    nano  
    nasm  
    pkg-config  
    tmux  
    wget  
    python3-pip  
    ruby-dev  
    radare2

RUN pip3 install --upgrade pip

RUN python3 -m pip install --no-cache-dir autopep8 capstone  colorama  cython  keystone-engine  pefile  pwntools  qiling  rzpipe  ropgadget  ropper  sudo  unicorn  z3-solver    tabulate

RUN pip3 install angr angrop
RUN cd /opt/ && git clone https://github.com/angr/angrop && cd angrop && pip3 install .
RUN wget -O /bin/pwninit https://github.com/io12/pwninit/releases/download/3.2.0/pwninit && chmod +x /bin/pwninit 
RUN cd /opt/ && git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
RUN gem install one_gadget seccomp-tools && rm -rf /var/lib/gems/2.*/cache/*
RUN apt-get update -qq -y && apt-get install -qq -y patchelf elfutils
