CC=gcc
CFLAGS=-g -Wall

SOURCE_DIR=source
BUILD_DIR=build

PROGRAMS := $(subst .c,,$(subst $(SOURCE_DIR)/,,$(wildcard $(SOURCE_DIR)/*.c)))

all: $(PROGRAMS)

clean:
	$(RM) $(foreach p,$(PROGRAMS),$(BUILD_DIR)/$(p))

$(PROGRAMS):
	$(CC) $(CFLAGS) -o $(BUILD_DIR)/$@ $(SOURCE_DIR)/$@.c

.PHONY: all clean
