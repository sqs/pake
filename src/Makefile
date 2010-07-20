SRC=pake.c
OBJ=$(SRC:.c=.o)
OUT=../libpake.so
INCLUDES=-I. -I../src
LIBS=-L/usr/local/lib -lssl
CFLAGS+=-fPIC
LDFLAGS=-g

.SUFFIXES: .c

default: $(OUT)

%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	gcc -shared -o $(OUT) $(OBJ)

depend: dep

dep:
	makedepend -- $(CFLAGS) -- $(INCLUDES) $(SRC)

clean:
	rm -f $(OBJ) $(OUT) 