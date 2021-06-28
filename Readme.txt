# Barracuda - Fortinet Converter Script

## on FMG
  create policy folder and package
  then --> change in code


## get files:
  addresses ,services and policies via copy paste from UI
  policies also download fwrule7 file!

  remove headers from files !!!

## pre run
  set environ variables

  *export fgmuser=<admin>*
  *export fgmpass=<password>*


  create address-group  : "Internet" first only with "all"
      not sure if we need them anymore: IP__NOT 10.0.0.0/8 ,  IP__NOT 172.16.0.0/12 , IP__NOT 192.168.0.0/16
  create addr obj       : "PascomServer"  ( Any , ALL )
  create schedule       : "tbd"
  create service        :


## after run:
  Check errors and comments!

  policy  :
    schedule : check all with "tbd"

## finally
  finish "Internet"	= ALL , NOT 10.0.0.0/8 , NOT 172.16.0.0/12 , NOT 192.168.0.0/16
