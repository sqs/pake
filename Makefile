export CC=gcc
export CFLAGS=-Wall -Werror -g
export LD=compat-ld

.PHONY: test clean

default: build

build:
	$(MAKE) -C src

test: build
	$(MAKE) -C test

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean
