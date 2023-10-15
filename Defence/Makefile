CC = gcc
SRCS = srcs/defence.c srcs/defence_utils.c srcs/ip_container.c
OUTS = srcs/defence.o srcs/defence_utils.o srcs/ip_container.o
INCS = incs
TARGET = defence.out

.c.o:
	$(CC) -c -o $@ $< -I $(INCS)

all: $(OUTS)
	$(CC) -o $(TARGET) $(OUTS) -lpcap

clean:
	rm -f srcs/*.o
	rm -f $(TARGET)
