# Barracuda - Fortinet Converter Script
  only usable for special use cases

## get files:
    addresses ,services and policies via copy paste from UI
    policies: add comment as column 1 and download also "*.fwrule7" file!

    remove headers from files !!!

## tasks on FMG
    create policy folder and package
    then --> change in code

    create address-group  : "Internet" first only with "all"
        not sure if we need them anymore: IP__NOT 10.0.0.0/8 ,  IP__NOT 172.16.0.0/12 , IP__NOT 192.168.0.0/16
    create addr obj       : "PascomServer"  ( Any , ALL )
    create schedule       : "tbd"

    create shaper : see inline in code line 43 to 57

## pre run
    set environ variables

    edit global variables in code : see line 28 -40

    *export fmguser= -admin-*
    *export fmgpass= -password-*


## after run:
    Check errors and comments!

    addresses:
      finish "Internet"	= ALL , NOT 10.0.0.0/8 , NOT 172.16.0.0/12 , NOT 192.168.0.0/16

    services:
      see comment : " <<check !! "
      see red Icons

    policy  :
      see schedule : check all with "tbd"
      see comments : starting with ">>"
      see rules ending _bw : check if necessary
