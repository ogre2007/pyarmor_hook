NAME=pyarmor_hook

CFLAGS=-D__USE_GNU -D_GNU_SOURCE -fPIC 

all:
	gcc $(CFLAGS) -c -o re_mprot.o re_mprot.c
	gcc $(CFLAGS) -c -o $(NAME).o $(NAME).c
	gcc $(CFLAGS) -shared -o $(NAME).so $(NAME).o re_mprot.o -ldl

clean:
	rm -f *.so *.o
