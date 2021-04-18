import socket
import argparse
import re

Parse = argparse.ArgumentParser(description='Vuln Finder')

# Main Arguments
Parse.add_argument("--target",dest="target",help="target IP",required=True)
Parse.add_argument("--port",dest="port",help="target PORT",required=True)

args = vars(Parse.parse_args())

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.connect((args['target'],int(args['port'])))
sock.settimeout(2)

query = "GET / HTTP/1.1\nHost: "+args['target']+"\n\n"
http_get = bytes(query,'utf-8')

data = ''
with open('vulns.txt','r') as file:
    vulns = file.read()

try:
    sock.sendall(http_get)
    data = sock.recvfrom(1024)
    data = data[0]
    print(data)
except e:
    print(e)