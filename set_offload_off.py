#!/usr/bin/python3
#
#(C)'2021 by Herby
# V 1.1
# 2021-12-06
#
import requests
import time
from datetime import datetime
import json
import sys
import urllib3
import os
import re
from colorama import Fore
from colorama import Style
from pprint import pprint
import getpass
import random
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# change this !!  --------------------------------------------------
url = "https://192.168.0.232/jsonrpc"
adom = "lga6" #"root" #
log_prefix = "log/check_"
sim = "no" # oder yes # simulate set
# change this !!  --------------------------------------------------

headers = {"'Content-Type": "application/json"}
sid = ""

html_header="""<!DOCTYPE html>
<html>
<head>
<style>
p.small {
  line-height: 0.3;
}

p.big {
  line-height: 1.8;
}
</style>
</head>
<body>
"""

html_footer="""</body>

</html>
"""

return_ok=0
return_false=0

G="G"
R="R"
B="B"
M="M"

def log(msg,color):
    # colors G = green, R=red B=blue, M= MAGENTA
    # only red is written to log-file
    # all is written to html
    #
    # Green     : OK
    # Magenta   : OK, but something needs to be checked manually
    # RED       : ERROR
    # Blue      : information
    # yellow    : disaster :-)

    msg=str(msg)

    try:
        if color==G:  #green
            print(f'{Fore.GREEN}{msg}{Style.RESET_ALL}')
            htmllog.write('<p style="color:green;" class="small">')
            htmllog.write(msg)
            htmllog.write('</p>'+"\n")
        if color==R:  #red
            print(f'{Fore.RED}{msg}{Style.RESET_ALL}')
            htmllog.write('<p style="color:red;">')
            htmllog.write(msg)
            htmllog.write('</p>'+"\n")
            textlog.write(msg+"\n")

        if color==B:  #blue
            print(f'{Fore.BLUE}{msg}{Style.RESET_ALL}')
            htmllog.write('<p style="color:blue;">')
            htmllog.write(msg)
            htmllog.write('</p>'+"\n")
        if color==M:
            print(f'{Fore.MAGENTA}{msg}{Style.RESET_ALL}')
            htmllog.write('<p style="color:magenta;">')
            htmllog.write(msg)
            htmllog.write('</p>'+"\n")


    except Exception as e:
        print(f'{Fore.YELLOW}{e}{Style.RESET_ALL}')
        raise

def api_call(data):

    retry=0
    rep_err = False
    #print(json.dumps(data))
    try:
        rep = requests.post(url,headers=headers, data=json.dumps(data),verify=False )
    except Exception:
        rep_err = True
        pass
    rep_text=rep.text
    if  rep_err:
        log("error during get, check ip",R)
        return ""

    if rep.status_code == 503:

        rep_text=""

    if rep.status_code != 200:
        log(80*"=",R)
        log(f'Something went wrong. status_code: {rep.status_code}',R)
        log (rep_text,R)
        log (data,R)
        log(80*"=",R)
        return ""

    #return result
    s=json.loads(rep.text)
    return s

def log_result(r,name,l,override_green=G):
    global return_ok
    global return_false

    id=""

    if r == "":
        return_false +=1
        pr= "<<< unkown error, see above  >>>"
        color=R
    else:
        d = r["result"][0]
        status = d["status"]
        #print("status =", d["status"])
        if status["code"] in [0,-2]:
            return_ok +=1
            try:
                id = d["data"]["policyid"]
            except:
                pass
            color=override_green
            pr=(f'-- ok:id {id} | {status["message"]} :{name}')

        elif status["code"] == -9998:
            pr=(name+" - "+json.dumps(status))
            return_false +=1
            color=R
        else:
            pr=(name+" - "+json.dumps(status)+"  |  "+ str(r))
            return_false +=1
            color=R

    log(f'{l} | {pr}',color)
    return id

def get_session_token():  # and open log files
    global textlog,htmllog
    username=""
    password=""
    try:
        username = os.environ['fmguser']
        password = os.environ['fmgpass']
    except Exception:
        pass

    if username == "":
        username = input("Enter FortiManager Username: ")

    if password == "":
        print("Enter FortiManager Password: ")#, end='')
        password = getpass.getpass()

    data = {"method": "exec", "params": [{"data": {"passwd": password, "user": username}, "url": "sys/login/user"}], "session": "null"}

    s = api_call( data )

    if s != "":
        logfile = log_prefix+time.strftime("%Y.%m.%d-%H%M")+".log"
        textlog=open(logfile,"w")
        htmlfile = log_prefix+time.strftime("%Y.%m.%d-%H%M")+".html"
        htmllog=open(htmlfile,"w")
        htmllog.write(html_header+"\n")
        return s["session"]
    else:
        print ("got no session ID")
        sys.exit(1)

def fmg_logout():  # and close log files
    data = {"id": 1, "method": "exec", "params": [ { "url": "/sys/logout" } ],
        "session": sid}
    r = api_call( data )

    now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"-- script finished at {now} ",R)

    textlog.close()
    htmllog.write(html_footer+"\n")
    htmllog.close()

def get_pkg_sub(act_folder,subobjs):
    for subobj in subobjs:
        if "subobj" in subobj:
            get_pkg_sub(act_folder+"/"+subobj["name"],subobj["subobj"])
        else:
            pkg= (act_folder+"/"+subobj["name"])
            #print (pkg)
            set_aao("pkg"+pkg)

def update_pkgs():
    suburl="obj/firewall/address"
    dataurl = f'/pm/pkg/adom/{adom}'
    data = {"method": "get", "params": [{
        "url":dataurl }],
        "session": sid}
    r = api_call( data )
    d = r["result"][0]["data"]
    get_pkg_sub("",d) # check tree recursiv

def update_pblocks():
    suburl="obj/firewall/address"
    dataurl = f'/pm/pblock/adom/{adom}'
    data = {"method": "get", "params": [{
        "url":dataurl }],
        "session": sid}
    r = api_call( data )
    d = r["result"][0]["data"]

    for pb in d:
        pblock=pb["name"]
        #print(pblock)
        set_aao("pblock/"+pblock)

def set_aao(pkg_pb):  # set auto-asic-offload to offload
    suburl="firewall/policy"
    dataurl = f'/pm/config/adom/{adom}/{pkg_pb}/{suburl}'
    data = {"method": "get", "params": [{
        "url":dataurl }],
        "session": sid}

    r = api_call( data )
    d = r["result"][0]["data"]
    print("Working on:",pkg_pb)
    #pprint(d)
    for pol in d:
        if "auto-asic-offload" in pol:
            if pol["auto-asic-offload"] != 0:
                suburl=f'firewall/policy/{pol["policyid"]}'
                update={}
                update["auto-asic-offload"]=0
                dataurl = f'/pm/config/adom/{adom}/{pkg_pb}/{suburl}'
                data = {"method": "update", "params": [{
                    "data":update,
                    "url":dataurl }],
                    "session": sid}
                tolog=f'{pkg_pb},{pol["policyid"]},{pol["name"]},{pol["auto-asic-offload"]}->0'
                if sim == "yes":
                    print(tolog)
                    continue
                r = api_call( data )
                #print(data)
                log_result(r,tolog,0)

#----------------------------------------------------------------------------
#main

user=getpass.getuser()

# get token
sid = get_session_token()
cmd = ' '.join(sys.argv[0:])
now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
log(f"-- script run from {user} at {now} with cmd: {cmd}",R)

update_pblocks()
update_pkgs()

fmg_logout()
