#Makefile
all: send_arp

send_arp: send_arp.o
	gcc -o send_arp send_arp.o -lpcap 

send_arp.o: send_arp.cpp
	gcc -c -o send_arp.o send_arp.cpp -lpcap

clean:
	rm -f send_arp
	rm -f *.o