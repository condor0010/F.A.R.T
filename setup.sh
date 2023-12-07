apt update -y
apt install -y systemd-coredump g++ gcc gcc-multilib gdb gdb-multiarch git locales make man nano nasm pkg-config tmux wget python3-pip ruby-dev meson sudo
pip3 install --upgrade pip 
python3 -m pip install --no-cache-dir autopep8 capstone colorama cython keystone-engine pefile pwntools qiling rzpipe ropgadget ropper sudo unicorn z3-solver tabulate --break-system-packages
pip3 install angr angrop --break-system-packages
cd /opt/ && git clone https://github.com/angr/angrop && cd angrop && pip3 install .
wget -O /bin/pwninit https://github.com/io12/pwninit/releases/download/3.2.0/pwninit && chmod +x /bin/pwninit 
cd /opt/ && git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
gem install one_gadget seccomp-tools && rm -rf /var/lib/gems/2.*/cache/*
apt-get update -qq -y && apt-get install -qq -y patchelf elfutils
cd /
git clone https://github.com/rizinorg/rizin
cd rizin
meson setup build
meson compile -C build
sudo meson install -C build
