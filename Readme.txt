on FMG
  create policy folder package



get files:
  addresses ,services and policies via copy paste
  policies also fwrule7 file!

  remove headers from file !!!

pre run

export fgmuser=<admin>
export fgmpass=<password>


Internet	4 internal,  2 external	Ref: World , NOT 10.0.0.0/8 , NOT 172.16.0.0/12 , NOT 192.168.0.0/16	16oct2007/wrzul

  create address-group  : "Internet" IP__NOT 10.0.0.0/8 ,  IP__NOT 172.16.0.0/12 , IP__NOT 192.168.0.0/16
  create addr obj       : "PascomServer"  ( Any , ALL )
  create schedule       : "tbd"
  create service        :


after run:

policy  :
  schedule : check all with "tbd"
