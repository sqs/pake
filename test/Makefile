SRC=test_pake.c
OBJ=$(SRC:.c=.o)
OUT=test_pake
INCLUDES=-I. -I../src
LIBS=-L.. -lpake -lssl
LDFLAGS=-g

.PHONY: test

test: test_pake
	LD_LIBRARY_PATH=.. ./test_pake

%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ) ../libpake.so
	$(CC) $(LIBS) $(LDFLAGS) -o $@ $(OBJ)

clean:
	rm -f $(OBJ) $(OUT)