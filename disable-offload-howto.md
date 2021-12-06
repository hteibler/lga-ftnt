# How to disable ASIC offloading

## Set on all policies = initial run

### use script "set_offload_off.py"

1. edit global parameter in code
2. set username and password in environment
```
export fmguser= -admin-
export fmgpass= -password-
```

to simulate a run ( makes no changes! ),
edit global parameter ```
 sim = "no"```

## install backend service

### use script "lga_srv.py"

tasks around the script
1. edit parameter in code "lga_serv.py"
2. edit "lga_fmg.service"
3. cp lga_fmg.service /etc/systemd/system/
4. sudo service lga_fmg start

it is also possible to run the script standalone, especially for testing

in FMG CLI:

```
config system syslog
  edit "lga-syslog"
      set ip <ip-off-service>
      set port 10514
  next
end
config system locallog syslogd setting
  set severity information
  set status enable
  set syslog-name "lga-syslog"
end
```
