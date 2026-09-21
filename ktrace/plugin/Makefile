CFLAGS = -O2 -Wall -Werror -fPIC $(shell pkg-config --cflags glib-2.0)

oracle.so: oracle.c qemu-plugin.h
	$(CC) $(CFLAGS) -shared -o $@ oracle.c

clean:
	rm -f oracle.so
