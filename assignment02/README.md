**SIMANTIKO: STO ACMONITOR YPARXEI MIA METAVLITI ME ONOMA MD5_HASH, PREPEI NA ALLAXTEI**


How to setup:

- Download all files in the same folder
in the terminal type:
- make
- LD_PRELOAD=./logger.so ./test_aclog
the test_aclog will create some files and the logging file
- run ./acmonitor -(whatever flag) to test other stuff

Nomizw oti spaei to acmonitor se kapoia fash alla den exw vrei giati
to logger pantws fainetai na doylevei swsta

*** Ousiastika me to LD_PRELOAD toy leme pare tin f_open poy ftiaksame sto logger.c
alliws an den to kanoyme auto tote tha parei tin default f_open kai den tha ftiaksei to
logging arxeio ***
