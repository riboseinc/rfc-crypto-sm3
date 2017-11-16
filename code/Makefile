.PHONY: clean

CFLAGS = 

DEPS = sm3.h
OBJ = sm3.o sm3_main.o print.o
CC = c99

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

sm3_test: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJ) sm3_test

