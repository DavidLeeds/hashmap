TOP_DIR := $(CURDIR)/..
SRC_DIR := $(TOP_DIR)/src

TARGET_EXEC := hashmap_test

SOURCES := $(SRC_DIR)/hashmap.c hashmap_test.c

CFLAGS += -O0 -g -ggdb -Wall -Wunused -Werror -I$(SRC_DIR)

OBJS := $(SOURCES:%.c=%.o)


test: $(TARGET_EXEC)

$(TARGET_EXEC): $(OBJS)
	@echo EXEC $@ ; \
	$(CC) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET_EXEC)

.PHONY: test clean
