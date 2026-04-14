CC = gcc
CLANG = clang

# Thêm -I/usr/local/include để nhận diện header mới
CFLAGS = -D_GNU_SOURCE -Iinc -I/usr/local/include -Wall -O2 $(shell pg_config --includedir 2>/dev/null | xargs -I{} echo -I{})

# Quan trọng: Thêm -L/usr/local/lib để Linker tìm thấy libxdp/libbpf mới của Server 1
LDFLAGS = -L/usr/local/lib -lxdp -lbpf -lpthread -lssl -lcrypto -lpq

BPF_CFLAGS = -O2 -target bpf -g
KERNEL_HEADERS = /usr/include

BIN_DIR = bin

SRC = main.c src/main_diag.c src/config.c src/db_config.c src/interface.c src/forwarder.c src/wan_arp.c src/crypto_policy_utils.c src/crypto_dispatch.c src/packet_crypto.c src/crypto_layer2.c src/crypto_layer3.c src/crypto_layer4.c src/flow_table.c src/fragment.c
OBJ = $(SRC:.c=.o)
TARGET = $(BIN_DIR)/network-encryptor

BPF_SRC = bpf/xdp_redirect.c bpf/xdp_wan_redirect.c
BPF_OBJ = bpf/xdp_redirect.o bpf/xdp_wan_redirect.o

.PHONY: all clean run dirs

all: dirs $(BPF_OBJ) $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Bổ sung -I/usr/local/include cho phần BPF để đồng bộ
bpf/%.o: bpf/%.c
	$(CLANG) $(BPF_CFLAGS) -I$(KERNEL_HEADERS) -I/usr/local/include -c $< -o $@

clean:
	rm -rf $(BIN_DIR) src/*.o *.o $(BPF_OBJ)

run:
	sudo DB_URL="host=localhost user=postgres dbname=xdpdb" $(TARGET) -id 1
