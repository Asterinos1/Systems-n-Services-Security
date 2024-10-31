all: logger acmonitor test_aclog


logger: logger.c
	gcc -fPIC -shared -o logger.so logger.c -ldl -lcrypto
 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog


run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog


clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor

