CFLAGS = -O2 -g -Wall -Werror -std=gnu99 -D_GNU_SOURCE
LDFLAGS = -Ilib -Llib -lnvme

QUIET_CC = @echo '   ' CC $@;

test: test/test.c libnvme
	$(QUIET_CC)$(CC) $(CPPFLAGS) $(CFLAGS) $< -o test/test $(LDFLAGS)

libnvme:
	@$(MAKE) -C lib/

clean:
	rm -f test/test
	$(MAKE) -C lib clean


.PHONY: libnvme test
