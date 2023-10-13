SYN_EXE = ./SYN-Flood/exe
CFLAGS += -w
SYN_STORE = ./SYN-Flood/IPNumbersCreated.txt ./SYN-Flood/interface.conf

syn: SYN-Flood/syn_flood.o SYN-Flood/syn_flood_utils.o
	$(CC) -o $(SYN_EXE) $^

synrun:
	sudo ./$(SYN_EXE)

synclean: 
	rm -f $(SYN_STORE)
	rm -f $(SYN_EXE)

clean:
	rm -rf $(VLAN_EXE) $(SYN_EXE) $(SYN_STORE)
	rm -rf SYN-Flood/syn_flood.o SYN-Flood/syn_flood_utils.o

