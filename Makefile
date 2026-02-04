#
# DistributionVC - Data Aggregation with SGX and WolfTLS
# Main Makefile for building all components
#

SGX_SDK ?= $(HOME)/sgx_lab/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

# WolfSSL configuration
WOLFSSL_PATH ?= $(HOME)/wolfssl_install
WOLFSSL_ROOT ?= $(HOME)/sgx_lab/wolfssl
WOLFSSL_SGX_LIB := $(WOLFSSL_ROOT)/IDE/LINUX-SGX
WOLFSSL_INCLUDE := -I$(WOLFSSL_PATH)/include
WOLFSSL_LIB := -L$(WOLFSSL_PATH)/lib -lwolfssl

# Include SGX SDK buildenv for proper configuration
include $(SGX_SDK)/buildenv.mk

ifeq ($(SGX_ARCH), x86)
    SGX_COMMON_FLAGS := -m32
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_TRUSTED_LIBRARY_PATH := $(SGX_SDK)/lib
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
    SGX_COMMON_FLAGS := -m64
    SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_TRUSTED_LIBRARY_PATH := $(SGX_SDK)/lib64
    SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
    SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_FLAGS += -O0 -g
else
    SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

ifneq ($(SGX_MODE), HW)
    SGX_URTS_LIB := sgx_urts_sim
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
    SGX_URTS_LIB := sgx_urts
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

######## Enclave Settings ########

ENCLAVE_DIR := Enclave
ENCLAVE_NAME := enclave.so
SIGNED_ENCLAVE_NAME := enclave.signed.so
ENCLAVE_CONFIG_IFILE := $(ENCLAVE_DIR)/Enclave.config.xml
ENCLAVE_CPP_SRCS := $(ENCLAVE_DIR)/Enclave.cpp
ENCLAVE_U_C := $(ENCLAVE_DIR)/Enclave_u.c
ENCLAVE_U_H := $(ENCLAVE_DIR)/Enclave_u.h
ENCLAVE_T_C := $(ENCLAVE_DIR)/Enclave_t.c
ENCLAVE_T_H := $(ENCLAVE_DIR)/Enclave_t.h

ENCLAVE_INCLUDE_PATHS := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx \
                         -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/wolfcrypt
ENCLAVE_CFLAGS := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector \
                  $(ENCLAVE_INCLUDE_PATHS) -fno-builtin -fno-builtin-printf -I. \
                  -DWOLFSSL_SGX -DWOLFSSL_CUSTOM_CONFIG
ENCLAVE_CXXFLAGS := $(ENCLAVE_CFLAGS) -nostdinc++ -std=c++11

ENCLAVE_LDFLAGS := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
                   -L$(WOLFSSL_SGX_LIB) -lwolfssl.sgx.static.lib \
                   -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
                   -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
                   -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                   -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
                   -Wl,--defsym,__ImageBase=0 \
                   -Wl,--version-script=$(ENCLAVE_DIR)/Enclave.lds

######## App Settings ########

APP_DIR := App
APP_NAME := server
APP_CPP_SRCS := $(APP_DIR)/Server.cpp
APP_CXXFLAGS := $(SGX_COMMON_CXXFLAGS) -I$(SGX_SDK)/include -I$(ENCLAVE_DIR) $(WOLFSSL_INCLUDE)
APP_LDFLAGS := -L$(SGX_LIBRARY_PATH) -l$(SGX_URTS_LIB) -lpthread $(WOLFSSL_LIB) -Wl,-rpath,$(WOLFSSL_PATH)/lib

######## Receiver Settings ########

RECEIVER_DIR := Receiver
RECEIVER_NAME := receiver_client
RECEIVER_CPP_SRCS := $(RECEIVER_DIR)/client.cpp
RECEIVER_CXXFLAGS := $(SGX_COMMON_CXXFLAGS) $(WOLFSSL_INCLUDE) -IInclude
RECEIVER_LDFLAGS := -lpthread $(WOLFSSL_LIB) -Wl,-rpath,$(WOLFSSL_PATH)/lib

######## DataServer Settings ########

DATASERVER_DIR := DataServer
DATASERVER_NAME := relay_server
DATASERVER_CPP_SRCS := $(DATASERVER_DIR)/relay.cpp
DATASERVER_CXXFLAGS := $(SGX_COMMON_CXXFLAGS) $(WOLFSSL_INCLUDE) -IInclude
DATASERVER_LDFLAGS := -lpthread $(WOLFSSL_LIB) -Wl,-rpath,$(WOLFSSL_PATH)/lib

.PHONY: all clean

all: bin/$(APP_NAME) bin/$(RECEIVER_NAME) bin/$(DATASERVER_NAME) bin/$(SIGNED_ENCLAVE_NAME)
	@echo ""
	@echo "=== DistributionVC Build Complete ==="
	@echo "Enclave:     bin/$(SIGNED_ENCLAVE_NAME)"
	@echo "Server:      bin/$(APP_NAME)"
	@echo "Receiver:    bin/$(RECEIVER_NAME)"
	@echo "DataServer:  bin/$(DATASERVER_NAME)"
	@echo ""
	@echo "To run:"
	@echo "  1. In terminal 1: ./bin/$(APP_NAME)"
	@echo "  2. In terminal 2: ./bin/$(DATASERVER_NAME) 1"
	@echo "  3. In terminal 3: ./bin/$(DATASERVER_NAME) 2"
	@echo "  4. In terminal 4: ./bin/$(RECEIVER_NAME) \"Hello from receiver\""

######## Enclave Build ########

$(ENCLAVE_T_C): $(ENCLAVE_DIR)/Enclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted Enclave.edl --search-path $(SGX_SDK)/include
	@echo "Generated trusted code for enclave"

$(ENCLAVE_T_H): $(ENCLAVE_T_C)

$(ENCLAVE_DIR)/Enclave_t.o: $(ENCLAVE_T_C)
	@$(CXX) $(ENCLAVE_CXXFLAGS) -c $< -o $@
	@echo "Compiled $<"

$(ENCLAVE_DIR)/Enclave.o: $(ENCLAVE_CPP_SRCS) $(ENCLAVE_T_H)
	@$(CXX) $(ENCLAVE_CXXFLAGS) -c $(ENCLAVE_CPP_SRCS) -o $@
	@echo "Compiled $(ENCLAVE_CPP_SRCS)"

$(ENCLAVE_NAME): $(ENCLAVE_DIR)/Enclave.o $(ENCLAVE_DIR)/Enclave_t.o
	@$(CXX) $^ -o $@ $(ENCLAVE_LDFLAGS)
	@echo "Linked $(ENCLAVE_NAME)"

bin/$(SIGNED_ENCLAVE_NAME): $(ENCLAVE_NAME)
	@mkdir -p bin
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_DIR)/Enclave_private_test.pem \
		-enclave $(ENCLAVE_NAME) -out $@ -config $(ENCLAVE_CONFIG_IFILE)
	@echo "Signed enclave: $@"

######## App Build ########

$(ENCLAVE_U_C): $(ENCLAVE_DIR)/Enclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --untrusted Enclave.edl --search-path $(SGX_SDK)/include
	@echo "Generated untrusted code for app"

$(ENCLAVE_U_H): $(ENCLAVE_U_C)

$(ENCLAVE_DIR)/Enclave_u.o: $(ENCLAVE_U_C) $(ENCLAVE_U_H)
	@$(CC) $(SGX_COMMON_CFLAGS) -c $(ENCLAVE_U_C) -I$(ENCLAVE_DIR) -I$(SGX_SDK)/include -o $@
	@echo "Compiled $(ENCLAVE_U_C)"

$(APP_DIR)/Server.o: $(APP_CPP_SRCS) $(ENCLAVE_U_H)
	@$(CXX) $(APP_CXXFLAGS) -c $(APP_CPP_SRCS) -o $@
	@echo "Compiled $(APP_CPP_SRCS)"

bin/$(APP_NAME): $(APP_DIR)/Server.o $(ENCLAVE_DIR)/Enclave_u.o
	@mkdir -p bin
	@$(CXX) $^ -o $@ $(APP_LDFLAGS)
	@echo "Linked bin/$(APP_NAME)"

######## Receiver Build ########

bin/$(RECEIVER_NAME): $(RECEIVER_CPP_SRCS)
	@mkdir -p bin
	@$(CXX) $(RECEIVER_CXXFLAGS) -c $(RECEIVER_CPP_SRCS) -o Receiver/client.o
	@$(CXX) Receiver/client.o -o $@ $(RECEIVER_LDFLAGS)
	@echo "Linked bin/$(RECEIVER_NAME)"

######## DataServer Build ########

bin/$(DATASERVER_NAME): $(DATASERVER_CPP_SRCS)
	@mkdir -p bin
	@$(CXX) $(DATASERVER_CXXFLAGS) -c $(DATASERVER_CPP_SRCS) -o DataServer/relay.o
	@$(CXX) DataServer/relay.o -o $@ $(DATASERVER_LDFLAGS)
	@echo "Linked bin/$(DATASERVER_NAME)"

######## Clean ########

clean:
	@rm -f bin/$(APP_NAME) bin/$(RECEIVER_NAME) bin/$(DATASERVER_NAME) bin/$(SIGNED_ENCLAVE_NAME)
	@rm -f $(ENCLAVE_NAME) $(ENCLAVE_T_C) $(ENCLAVE_T_H) $(ENCLAVE_U_C) $(ENCLAVE_U_H)
	@rm -f $(ENCLAVE_DIR)/*.o $(APP_DIR)/*.o $(RECEIVER_DIR)/*.o $(DATASERVER_DIR)/*.o
	@rm -f $(ENCLAVE_DIR)/Enclave_t.* $(ENCLAVE_DIR)/Enclave_u.*
	@echo "Cleaned"

.PHONY: help
help:
	@echo "=== DistributionVC Makefile ==="
	@echo "Targets:"
	@echo "  make              - Build all components"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Build environment:"
	@echo "  SGX_MODE=$(SGX_MODE)"
	@echo "  SGX_ARCH=$(SGX_ARCH)"
	@echo "  SGX_DEBUG=$(SGX_DEBUG)"
