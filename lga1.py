#!/usr/bin/python3
#
#(C)'2021 by Herby
# V 1.1
# 2021-06-29
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
import pprint
import getpass
import random



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {"'Content-Type": "application/json"}
sid = ""

# change this !!  --------------------------------------------------
url = "https://192.168.0.231/jsonrpc"
adom = "lga5"
package="test1/glo1"
addresses = "network_objects_global.txt"
services ="services_global.txt"

new_objects_text="added via converter-script:"
new_addr_obj_prefix = "IP__"
new_addr_obj_prefix_pol = "IP_P_"
new_service_obj_prefix = "S__"
log_prefix = "log/run_"
# change end   ----------------------------------------------------

return_ok=0
return_false=0

G="G"
R="R"
B="B"
M="M"

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

def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

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
        #print(json.dumps(data))
        #sys.exit()

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

def get_session_token():  # and open log files
    global textlog,htmllog
    username = os.environ['fmguser']
    password = os.environ['fmgpass']

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

def make_addr(entry,data):
    entry=entry.strip()
    if entry[:3] == "DNS":  # FQDN
        data["type"]="fqdn"
        data["fqdn"]=data["name"]
        return True,data
    if is_valid_ipv4(entry):   # no mask = /32
        data["subnet"]=entry+"/32"
        data["type"]="ipmask"
        return True,data
    if entry.find('/') >0:  # / cidr notation
        data["subnet"]=entry
        data["type"]="ipmask"
        return True,data
    if entry.find('-') >0:  # - ip range - notation eg.10.68.192.191-197
        i=entry.find('-')
        startip=entry[0:i]
        data["start-ip"]=startip
        j=startip.rfind('.')
        data["end-ip"] = entry[0:j+1]+entry[i+1:]
        data["type"]="iprange"
        return True,data

    #wildcard??

    data["err"] = "was soll das"
    return False,data

def make_service(entry,data):
    # check "no-timeout" 2764800
    if "no-timeout" in data["name"]:
        data["session-ttl"] = "2764800" # what is the max?

    ports=entry.split(",")

    for port in ports:
        port=port.strip()

        if port[:4] == "ECHO":
            data["protocol"]="ICMP"
            comment="<< check !! "+data["comment"]
            comment=comment[:250] +(comment[250:] and "...")
            data["comment"] = comment
            data["color"]= 7
            return True,data
        else:
            if port[:3] in ["TCP","UDP"]:
                data["protocol"]="TCP/UDP/SCTP"
                portrange=port[:3].lower()+"-portrange"
                pp = port[4:].strip()
                if ("DCERPC" in pp) or ("ONCRPC" in pp) or ("EMPTY" in pp):
                    pp="7777"
                    comment="<< check !! "+data["comment"]
                    comment=comment[:250] +(comment[250:] and "...")
                    data["comment"] = comment
                    data["color"]= 7
                #remove everything exept 0-9 and -
                pp = ''.join(i for i in pp if i.isdigit() or i in '-')
                try:
                    data[portrange].append(pp.strip())
                except Exception as e:
                    data[portrange]=[]
                    data[portrange].append(pp.strip())

                if data[portrange]==['']:
                    data[portrange]=['1-65535']
                continue

            else:
                print("unknown:",port)
                return False,data

    #print("make:",data)
    return True,data

def test_get():
    suburl="obj/firewall/addrgrp"
    suburl="obj/firewall/service/custom"
    dataurl = f'/pm/config/adom/{adom}/{suburl}'


    suburl="firewall/policy"
    dataurl = f'/pm/config/adom/{adom}/pkg/{package}/{suburl}'

    data = {"method": "get", "params": [{
        "url":dataurl }],
        "session": sid}


    print(data)
    #return
    r = api_call( data )
    pprint.pprint(r)
    #print (json.dumps(r))
    return
    d = r["result"][0]["data"]

    s=json.dumps(d)
    print (s)
    print(100*".")

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
            pr=(f'-- ok:{status["message"]} :{name}')
            return_ok +=1
            try:
                id = d["data"]["policyid"]
            except:
                pass
            color=override_green

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

def add_obj(newdata,dataurl,method="add"):
    data = {"method": method, "params": [{
         "data":newdata,
         "url":dataurl }],
         "session": sid}
    r = api_call( data )
    return r

def add_service(newdata):
    suburl="obj/firewall/service/custom"
    dataurl = f'/pm/config/adom/{adom}/{suburl}'
    return add_obj(newdata,dataurl)

def add_service_grp(newdata):
    suburl="obj/firewall/service/group"
    dataurl = f'/pm/config/adom/{adom}/{suburl}'
    return add_obj(newdata,dataurl)

def add_addr(newdata):
    suburl="obj/firewall/address"
    dataurl = f'/pm/config/adom/{adom}/{suburl}'
    return add_obj(newdata,dataurl)

def add_addr_grp(newdata):
    suburl="obj/firewall/addrgrp"
    dataurl = f'/pm/config/adom/{adom}/{suburl}'
    #print("gep:",newdata)
    return add_obj(newdata,dataurl)

def add_pol(newdata,package):
    suburl="firewall/policy"
    dataurl = f'/pm/config/adom/{adom}/pkg/{package}/{suburl}'
    return add_obj(newdata,dataurl)

def set_section(newdata,package,policy_id):
    #/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}/section value (set)
    suburl="firewall/policy"
    dataurl = f'/pm/config/adom/{adom}/pkg/{package}/{suburl}/{policy_id}/section value'
    return add_obj(newdata,dataurl,method="set")

def parse_addr(runs):
    if runs == 1:
        f=open(addresses,"r")
        rest=open(addresses+"-Rest","w")
    if runs == 2:
        f=open(addresses+"-Rest","r")

    lines=f.readlines()
    l=0
    for line in lines:
        l+=1
        data={}
        line_elements=line.strip().split("\t")
        data["name"]=line_elements[0].strip()
        data["interface"]=['any']
        comment=""
        #print(l,line)
        try:
            comment=line_elements[3].strip()
        except:
            pass

        comment=comment[:250] +(comment[250:] and "...")
        data["comment"]=comment
        entry=(line_elements[2])

        #checks
        entry_items=entry.split(",")
        if len(entry_items)==1:
            if entry_items[0][:4] != "Ref:": # else make a group
                ok,data=make_addr(entry_items[0],data)
                if  ok:
                    r=add_addr(data)
                    #d = r["result"][0]
                    #status = d["status"]
                    if not(r["result"][0]["status"]["code"] in [0,-2]) and runs==1:
                        #add line to rest
                        rest.write(line)
                    log_result(r,data["name"],l)
                else:
                    log(f'{l} >>> error >>> {entry_items[0]}  {data} {line}',R)
                continue  # next line
        #create group
        members=[]
        for entry_item in entry_items:
            entry_item=entry_item.strip()
            if entry_item[:4]=="Ref:": # add this object to member
                #print(entry_item[5:12])
                if entry_item[5:12]=="<empty>": # empty hence non existing refernece
                    log(f'{l} || empty hence non existing refernece: {entry_item[5:]}',R)
                    continue
                members.append(entry_item[5:].strip())
            else:  # new object and add to member
                data={}
                data["name"]=new_addr_obj_prefix+entry_item.strip()
                data["comment"]=new_objects_text
                ok,data=make_addr(entry_item,data)
                r=add_addr(data)
                log_result(r,data["name"],l)
                members.append(data["name"])
        grp={}
        grp["name"]=line_elements[0].strip()
        grp["comment"]=comment
        grp["member"]=members
        r=add_addr_grp(grp)
        if runs==1:
            if r == "":
                rest.write(line)
            else:
                if (not(r["result"][0]["status"]["code"] in [0,-2])):
                #add line to rest
                    rest.write(line)

        log_result(r,grp["name"],l)

    log(80*"-",R)
    log("OK: "+str(return_ok),R)
    log("failed: "+str(return_false),R)
    if runs==1:
        rest.close()

def parse_service(group):
    # Name	References	Entries	Comment	Usage

    f=open(services,"r")
    lines=f.readlines()
    l=0
    for line in lines:
        l+=1
        data={}
        line_elements=line.strip().split("\t")
        name_org=line_elements[0].strip()

        data["name"]=name_org

        comment=""
        #print(l,line)
        try:
            comment=line_elements[3].strip()
        except:
            pass

        comment=comment[:250] +(comment[250:] and "...")
        data["comment"]=comment
        entry=""
        try:
            entry=line_elements[2].strip()
        except:
            pass

        if entry == "":
            entry = "TCP EMPTY"

        refernece=line_elements[1].strip()
        #check if 0
        if refernece == "0": continue
        #print("entry:",entry.find("Ref:"),entry)
        if "Ref:" not in entry:
            #servcie object
            if group: continue # only parse group
            ok,data=make_service(entry,data)
            if  ok:
                r=add_service(data)
                log_result(r,data["name"],l)
            else:
                log(f'{l} >>> error >>> {entry}  {data} {line}',R)
            continue  # next line
        else:
            if not(group): continue # do not parse group
            #print(l,line)
            entry_items=entry.split(",")
            members=[]
            for entry_item in entry_items:
                entry_item=entry_item.strip()
                if entry_item[:4]=="Ref:": # add this object to member
                    member=entry_item[5:].strip()
                    members.append(member)
                elif entry_item[:5]=="ALLIP":  # weird object, replace with any ip
                    members.append("ALL")
                else:  # new object and add to member
                    data={}
                    data["name"]=new_service_obj_prefix+entry_item.strip()
                    data["comment"]=new_objects_text
                    ok,data=make_service(entry_item,data)
                    r=add_service(data)
                    log_result(r,data["name"],l)
                    members.append(data["name"])
            grp={}
            grp["name"]=line_elements[0].strip()
            grp["comment"]=comment
            grp["member"]=members
            #print(l,grp)
            r=add_service_grp(grp)
            log_result(r,grp["name"],l)

    log(80*"-",R)
    log("OK: "+str(return_ok),R)
    log("failed: "+str(return_false),R)

def find_rule(rule7,rule_name): #get first line with name
    for i,line in enumerate(rule7):
        if rule_name in line:
            return i
    return -1

def find_value(rule7,value_name,start):
    value=""
    j=start
    while (value=="" or j<len(rule7)):
        if value_name in rule7[j]:
            value = rule7[j][len(value_name)+1:][1:-1]
            break
        j+=1
    return value,j

def get_list(rule7,rule_name,type):  # type :src  :dst  :srv
    start=find_rule(rule7,rule_name+":"+type)
    items=[]
    j=0
    if rule7[start+5] != "list={":  # no list
        value,list_start=find_value(rule7,"ref",start)
        if value.lower() in ['any','all']:
            #print(80*":",rule_name,value)
            value="all"
            if type == "srv":
                value="ALL"
        items.append(value)
        return items
    list_start=start+5
    list_open=True
    #print(rule_name+":"+type)
    while True:
        line=rule7[list_start+j].strip()
        j+=1
        if line=="":   # empty line
            continue
        if line=="}" and list_open: # first close }
            list_open = False
            continue
        if line=="}" and not list_open: # second close }
            break
        if line[:4] == "ref=": # add ref
            items.append(line[5:-1])
            list_open = True
            continue
        if line[:5] == "addr=": # add ref
            addr=line[6:-1]
            # create object
            data={}
            data["name"]=new_addr_obj_prefix_pol+addr
            data["comment"]=new_objects_text+" IP from policy :)"
            ok,data=make_addr(addr,data)
            r=add_addr(data)
            log_result(r,data["name"],-1)
            items.append(data["name"])
            list_open = True
            continue

    #print(items)
    return items

def short_name(name,comment):  # short name to <35 and write org-name to comment
    if len(name)>32:
        rnd=random.randrange(100,999)
        comment=f'{comment}#org-name:{name}#'
        name=f'{name[:28]}#{rnd}'
    return name,comment

def parse_rules(rule_file,rule_file7):
    #	nr Comment	Action	Name	Features	Service	Source	VR Instance	Destination	Application Policy	SSL Inspection Policy	User	Schedule	QoS	IPS Policy	Usage
    #   0   1       2          3       4            5      6          7         8           9                     10                  11      12        13      14          15  16

    # read rule_file7
    #rule7= open(rule_file7).read().splitlines().strip()

    with open(rule_file7) as f:
        rule7 = f.readlines()
    rule7 = [x.strip() for x in rule7]

#    rule_name = "NLK-G-NOEBDA-DICOM-TU"
#    value="bothWays"
#    r=find_rule(rule7,rule_name)
#    v=find_value(rule7,value,r)
#    print(v)
#    sys.exit()

    f=open(rule_file,"r")
    lines=f.readlines()
    f.close()
    l=0
    old_section=""
    section=""
    for line in lines:
        l+=1
        data={}
        override=G
        line_elements=line.strip().split("\t")
        if len(line_elements) == 2: # new section name
            section=line_elements[1].strip()
            #print("Section:",section)
            #sys.exit()
            continue
        # action, Block = deny   Pass=allow,
        #Pass Dynamic Src NAT [Proxydyn]
        #Pass Client

        #data["section value"]=section

        data["schedule"]=['always']
        if  line_elements[12].strip() != "Always":
            data["schedule"]=['tbd']

        data["comments"]=line_elements[1].strip()
        b_action=line_elements[2].strip()
        if "Block" in b_action:
            action="deny"
        if "Pass Client" in b_action:
            action="accept"
        else:
            if "Pass" in b_action:  # needs to be manually modified
                action="accept"
                data["comments"]=">> "+b_action+" << "+data["comments"]
                override=M
        data["action"]=action
        rule_name=line_elements[3].strip()
        data["name"],data["comments"]=short_name(rule_name,data["comments"])
        data["srcaddr"]=get_list(rule7,rule_name,"src")
        data["dstaddr"]=get_list(rule7,rule_name,"dst")
        service=get_list(rule7,rule_name,"srv")
        if service == []:
            service="NONE"
            data["comments"]=">> check service << "+data["comments"]
            override=M
        data["service"]=service
        data["dstintf"]=['any']
        data["srcintf"]=['any']
        data["logtraffic"]="all"

        value_name="bothWays"
        r=find_rule(rule7,rule_name)
        bothways,x=find_value(rule7,value_name,r)

        r=add_pol(data,package)
        policy_id=log_result(r,data["name"],l,override_green=override)

        #set Section
        if old_section != section:
            sec_data={}
            sec_data["name"]=section
            sec_data["attr"]="global-label"
            rs=set_section(sec_data,package,policy_id)
            log("New Section: "+section,B)
            old_section = section
        if bothways == "1":
            src=data["srcaddr"]
            data["srcaddr"]=data["dstaddr"]
            data["dstaddr"]=src
            bw = data["name"] + "_bw"
            #bw=bw[:33] +(bw[33:] and "..")
            data["name"] = bw
            data["comments"] += "# bothway-rule #"
            r=add_pol(data,package)
            log_result(r,data["name"],l,override_green=override)

    log(80*"-",B)
    log("OK: "+str(return_ok),B)
    log("failed: "+str(return_false),B)

#----------------------------------------------------------------------------
#main

user=getpass.getuser()
arg = sys.argv[1:]

if arg == []:
    print("what do you want to do:")
    print("-------------------------------")
    print("1: copy addess objects, first run")
    print("2: copy addess objects, left from first run ")
    print("3: copy services - without groups")
    print("4: copy service-groups")
    print("5: copy policy packages")
    print("t: run test (dev only)")
    print("")
    print("------------------------------")
    sys.exit(0)

# get token
sid = get_session_token()
cmd = ' '.join(sys.argv[0:])
now=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
log(f"-- script run from {user} at {now} with cmd: {cmd}",R)
arg = sys.argv[1]

if arg == "1":
    parse_addr(1)

if arg == "2":
    parse_addr(2)

if arg == "3":
    parse_service(group=False)

if arg == "4":
    parse_service(group=True)

if arg == "5":
    rule_file = "global_rules.txt"
    rule_file7 ="_global.fwrule7"

    parse_rules(rule_file,rule_file7)

if arg == "t":
    test_get()

fmg_logout()
