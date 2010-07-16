SRC=pake.c
OBJ=$(SRC:.c=.o)
OUT=../libpake.a
INCLUDES=-I. -I../src
LIBS=-L/usr/local/lib -lssl
LDFLAGS=-g

.SUFFIXES: .c

default: $(OUT)

%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	ar rcs $(OUT) $(OBJ)

depend: dep

dep:
	makedepend -- $(CFLAGS) -- $(INCLUDES) $(SRC)

clean:
	rm -f $(OBJ) $(OUT) 