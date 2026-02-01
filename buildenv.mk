#
# buildenv.mk - Build environment configuration
#

ifeq ($(SGX_SDK),)
    SGX_SDK := $(HOME)/sgx_lab/sgxsdk
endif

ifeq ($(WOLFSSL_PATH),)
    WOLFSSL_PATH := $(HOME)/wolfssl_install
endif

SGX_COMMON_FLAGS += -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

WOLFSSL_INCLUDE := -I$(WOLFSSL_PATH)/include
WOLFSSL_LIB := -L$(WOLFSSL_PATH)/lib -lwolfssl
