#!/usr/bin/python3
#(C)'2021 by Herby and Fortinet
# V 1.1
# 2021-12-06

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import requests
import socketserver
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#-------------------------------------------------------
# change this
LOG_FILE = 'lga-fmg.log'
url = "https://192.168.0.232/jsonrpc"
SYSLOG_PORT = 10514
USERNAME="apiadmin"
PASSWORD="api2021admin"
#-------------------------------------------------------

HOST = "0.0.0.0"
pkgs=[]
sid=""

def api_call(data):
    headers = {"'Content-Type": "application/json"}
    url = "https://192.168.0.232/jsonrpc"
    retry=0
    rep_err = False
    try:
        rep = requests.post(url,headers=headers, data=json.dumps(data),verify=False )
        rep_text=rep.text
    except Exception:
        rep_err = True
        pass

    if  rep_err:
        log("error during get, check ip")
        return ""

    if rep.status_code == 503:
        rep_text=""

    if rep.status_code != 200:
        log(80*"=")
        log(f'Something went wrong. status_code: {rep.status_code}')
        log (rep_text)
        log (data)
        log(80*"=")
        return ""

    s=json.loads(rep.text)
    return s

def log(msg):
    msg=str(msg)
    try:
        textlog.write(msg+"\n")
        print(msg)

    except Exception as e:
        #raise
        pass
    return

def get_session_token():  # and open log files
    global textlog #,htmllog,url
    username=USERNAME
    password=PASSWORD
    data = {"method": "exec", "params": [{"data": {"passwd": password, "user": username}, "url": "sys/login/user"}], "session": "null"}
    s = api_call( data )
    if s != "":
        textlog=open(LOG_FILE,"a")
        return s["session"]
    else:
        print ("got no session ID")
        sys.exit(1)

def fmg_logout():  # and close log files
    data = {"id": 1, "method": "exec", "params": [ { "url": "/sys/logout" } ],
        "session": sid}
    r = api_call( data )
    textlog.close()

def get_pkg_sub(act_folder,subobjs):
    for subobj in subobjs:
        if "subobj" in subobj:
            get_pkg_sub(act_folder+"/"+subobj["name"],subobj["subobj"])
        else:
            pkg= (act_folder+"/"+subobj["name"])
            pkgs.append(pkg)

def get_pkg(adom):
    global pkgs,sid
    pkgs=[]
    suburl="obj/firewall/address"
    dataurl = f'/pm/pkg/adom/{adom}'
    data = {"method": "get", "params": [{
        "url":dataurl }],
        "session": sid}
    r = api_call( data )
    d = r["result"][0]["data"]
    get_pkg_sub("",d) # check tree recursiv

def do_it(postdata):
    global sid
    data={}
    for item in postdata:
        key=item[:item.find("=")]
        value=item[item.find("=")+1:].replace('"','')
        if key == "changes":
            v=value.split(",")
            value={}
            for i in v:
                k=i[:i.find("=")]
                v=i[i.find("=")+1:]
                value[k]=v
        data[key]=value

    if data["changes"]["type"]=="fw_policy":
        sid = get_session_token()
        adom=data["adom"]
        policyid=data["changes"]["key"]
        pkg_pb=""
        if "pkgname" in data["changes"]:
            pp=data["changes"]["pkgname"]
            if not any(pp in s for s in pkgs):
                get_pkg(adom)
                #print(pkgs)
            pkg_pb=[s for s in pkgs if pp in s]
            pkg_pb="pkg"+pkg_pb[0]

        if "pblkname" in data["changes"]:
            pkg_pb="pblock/"+data["changes"]["pblkname"]

        if pkg_pb=="":
            print("WTF!!")
            return

        update={}
        update["auto-asic-offload"]=0
        suburl=f'firewall/policy/{policyid}'
        dataurl = f'/pm/config/adom/{adom}/{pkg_pb}/{suburl}'
        newdata = {"method": "update", "params": [{
            "data":update,
            "url":dataurl }],
            "session": sid}
        r = api_call( newdata )
        d = r["result"][0]
        status = d["status"]
        msg=f'{data["date"]} {data["time"]} User:{data["user"]} {data["userfrom"]} {data["adom"]}-{pkg_pb} ID:{data["changes"]["key"]} Status:{status}'
        #pprint(data)
        log(msg)

    fmg_logout()

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global sid
        data = bytes.decode(self.request[0].strip(), encoding="utf-8")
        if "type=fw_policy" in data:
            if not("JSON(" in data):
                socket = self.request[1]
                do_it(data[5:].split())

def run_syslog(port=SYSLOG_PORT):
    print('Starting syslog... at ',port)
    try:
        server = socketserver.UDPServer((HOST,port), SyslogUDPHandler)
        server.serve_forever(poll_interval=0.5)
    except (IOError, SystemExit):
        raise
    except KeyboardInterrupt:
        print ("Crtl+C Pressed. Shutting down.")

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run_syslog(port=int(argv[1]))
    else:
        run_syslog()
