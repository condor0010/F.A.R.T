import r2pipe, os

path = '../bins/'
for binary in os.listdir(path):
    riz = r2pipe.open(path+binary)
    print(binary + " " + riz.cmd('aaa; pdf @  sym.vuln | grep gets | awk -F \'sym.imp.\' \'{print $2}\' | awk \'{print $1}\' | uniq | tr -d \'\\n\''))
    #print("    " + riz.cmd('afl | grep win | awk -F \'sym.\' \'{print $2}\' | tr -d \'\\n\''), end="")
    riz.quit
