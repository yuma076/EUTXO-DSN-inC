CC = gcc
CFLAGS = -Wall -Wextra -MMD -MP -O2 -I/opt/homebrew/opt/openssl@3/include
LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

CFLAGS += -fsanitize=address
LDFLAGS += -fsanitize=address

TARGET = blockchain

SRC_DIR = src
OBJ_DIR = obj
SRC = $(wildcard $(SRC_DIR)/*.c)
OBJ = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))
DEP = $(OBJ:.o=.d)

ARGS ?= ./input/Userdata.txt

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

run: $(TARGET)
	MallocScribble=1 ./$(TARGET) $(ARGS)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

-include $(DEP)

.PHONY: all run clean