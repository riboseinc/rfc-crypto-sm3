.PHONY: clean

CFLAGS = -Wall -m32

DEPS = sm3.h
OBJ = sm3.o sm3_main.o print.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sm3_test: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJ) sm3_test

