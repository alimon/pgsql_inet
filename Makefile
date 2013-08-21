CC=cc -Wall -Werror -fpic
RM=rm -rf

all: libpgsql_inet.so

libpgsql_inet.so: inet_net_ntop.c inet_net_pton.c network.c
	$(CC) -shared -o $@ $^

clean:
	$(RM) libpgsql_inet.so

.PHONY: all clean
