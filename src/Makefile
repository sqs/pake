SRC=pake.c
OBJ=$(SRC:.c=.o)
OUT=../libpake.so
INCLUDES=-I. -I../src
LIBS=-L/usr/local/lib -lssl
CFLAGS+=-fPIC
LDFLAGS=-g -lssl

.SUFFIXES: .c

default: $(OUT)

%.o: %.c
	$(CC) $(INCLUDES) $(CFLAGS) -c $< -o $@

$(OUT): $(OBJ)
	gcc -shared $(LDFLAGS) -o $(OUT) $(OBJ)

clean:
	rm -f $(OBJ) $(OUT) 