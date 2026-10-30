CC       ?= gcc
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
MANDIR   ?= $(PREFIX)/share/man

TARGET   = ratelimit
SRCDIR   = src
OBJDIR   = obj
MANDIR_SRC = man

SOURCES  = $(wildcard $(SRCDIR)/*.c)
OBJECTS  = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))
DEPS     = $(OBJECTS:.o=.d)

WARNINGS  = -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wformat-security
HARDEN_C  = -O2 -g -fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
            -fPIE
HARDEN_L  = -pie -Wl,-z,relro,-z,now

CFLAGS   := -std=c11 $(WARNINGS) $(HARDEN_C) \
            -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -Isrc $(CFLAGS)
LDFLAGS  := $(HARDEN_L) $(LDFLAGS)
LDLIBS   := -lpthread -lm
DEPFLAGS  = -MMD -MP

.PHONY: all clean distclean install uninstall docker-deb docker-test sanitize

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "Build successful: ./$(TARGET)"

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

-include $(DEPS)

clean:
	rm -rf $(OBJDIR) $(TARGET)

distclean: clean
	rm -rf dist

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	install -D -m 0644 $(MANDIR_SRC)/ratelimit.1 $(DESTDIR)$(MANDIR)/man1/ratelimit.1

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	rm -f $(DESTDIR)$(MANDIR)/man1/ratelimit.1

# ── Debian package + integration tests (run inside Docker) ──
docker-deb:
	./scripts/build-deb.sh

docker-test: docker-deb
	docker build -f docker/Dockerfile.test -t ratelimit-test .
	docker run --rm --init ratelimit-test

# ── Sanitizer stress run (host, no Docker) ──
sanitize:
	./scripts/sanitize.sh
