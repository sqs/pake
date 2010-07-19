SRC=test_pake.c
OBJ=$(SRC:.c=.o)

OUT=test_pake
INCLUDES=-I. -I../src
LIBS=-L.. -lpake -lssl
LDFLAGS=-g

.PHONY: test

test: test_pake
	./test_pake

%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ) ../libpake.a
	$(CC) $(LIBS) $(LDFLAGS) -o $@ $(OBJ) ../libpake.a

clean:
	rm -f $(OBJ) $(OUT)