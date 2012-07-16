import subprocess
import os, sys

#Authentification
euid = os.geteuid()
if euid != 0:
    print "Script not started as Root. Running sudo..."
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    os.execlpe('sudo',  *args)

subprocess.Popen(["tshark -i 4 -R 'ssl.handshake.certificate' -V"], shell=True)
