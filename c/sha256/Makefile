CC ?= cc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -pedantic

sha256: sha256.c
	$(CC) $(CFLAGS) -o $@ $<

test: sha256
	./sha256 -t

clean:
	rm -f sha256

.PHONY: test clean
