CC = gcc
CLANG = clang
AR = ar

# Thêm -I/usr/local/include để nhận diện header mới
CFLAGS = -D_GNU_SOURCE -Iinc -I/usr/local/include -Wall -O2 $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})

# Quan trọng: Thêm -L/usr/local/lib để Linker tìm thấy libxdp/libbpf mới của Server 1
LDFLAGS = -L/usr/local/lib -lxdp -lbpf -lpthread -lssl -lcrypto -lpq

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin

APP_SRC = main.c src/main_diag.c src/interface.c src/forwarder.c src/wan_arp.c src/crypto_policy_utils.c src/crypto_dispatch.c src/packet_crypto.c src/crypto_layer2.c src/crypto_layer3.c src/crypto_layer4.c src/flow_table.c src/fragment.c
APP_OBJ = $(APP_SRC:.c=.o)
TARGET = $(BIN_DIR)/network-encryptor
DB_LIB_SRC = src/config.c src/db_config.c src/db_env.c src/db_runtime.c
DB_LIB_OBJ = $(DB_LIB_SRC:.c=.o)
DB_LIB = $(BIN_DIR)/libdb_loader.a
DB_TEST_SRC = src/db_loader_test.c src/main_diag.c
DB_TEST_OBJ = $(DB_TEST_SRC:.c=.o)
DB_TEST_TARGET = $(BIN_DIR)/db-loader-test

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

.PHONY: all clean run dirs

all: dirs $(BPF_OBJ) $(DB_LIB) $(TARGET) $(DB_TEST_TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(DB_LIB): $(DB_LIB_OBJ)
	$(AR) rcs $@ $(DB_LIB_OBJ)

$(TARGET): $(APP_OBJ) $(DB_LIB)
	$(CC) -o $@ $(APP_OBJ) $(DB_LIB) $(LDFLAGS)

$(DB_TEST_TARGET): $(DB_TEST_OBJ) $(DB_LIB)
	$(CC) -o $@ $(DB_TEST_OBJ) $(DB_LIB) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Bổ sung -I/usr/local/include cho phần BPF để đồng bộ
bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I/usr/local/include -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o *.o $(BPF_OBJ)

run:
	sudo DB_URL="host=localhost user=postgres dbname=xdpdb" $(TARGET) -id 1
