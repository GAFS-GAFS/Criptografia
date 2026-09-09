CXX := g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Wpedantic -MMD -MP -Iinclude
LDLIBS := -lcrypto

TARGET := securebridge
TEST_AFFINE := test_affinetrans
TEST_CRYPTO := test_crypto

LIB_SOURCES := \
	src/affinetrans.cpp \
	src/aes_cipher.cpp \
	src/rsa_cipher.cpp \
	src/file_utils.cpp \
	src/openssl_utils.cpp \
	src/sha256.cpp

LIB_OBJECTS := $(patsubst %.cpp,build/%.o,$(LIB_SOURCES))
APP_OBJECTS := build/src/main.o $(LIB_OBJECTS)
TEST_AFFINE_OBJECTS := build/tests/test_affinetrans.o $(LIB_OBJECTS)
TEST_CRYPTO_OBJECTS := build/tests/test_crypto.o $(LIB_OBJECTS)
DEPENDENCIES := $(APP_OBJECTS:.o=.d) \
	$(TEST_AFFINE_OBJECTS:.o=.d) \
	$(TEST_CRYPTO_OBJECTS:.o=.d)

.PHONY: all clean clean-generated clean-all limpar test

all: $(TARGET)

$(TARGET): $(APP_OBJECTS)
	$(CXX) $(APP_OBJECTS) -o $@ $(LDLIBS)

$(TEST_AFFINE): $(TEST_AFFINE_OBJECTS)
	$(CXX) $(TEST_AFFINE_OBJECTS) -o $@ $(LDLIBS)

$(TEST_CRYPTO): $(TEST_CRYPTO_OBJECTS)
	$(CXX) $(TEST_CRYPTO_OBJECTS) -o $@ $(LDLIBS)

build/src/%.o: src/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

build/tests/%.o: tests/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

test: $(TEST_AFFINE) $(TEST_CRYPTO)
	./$(TEST_AFFINE)
	./$(TEST_CRYPTO)

clean:
	rm -rf build $(TARGET) $(TEST_AFFINE) $(TEST_CRYPTO)

clean-generated:
	@find data/encrypted data/recovered results -type f -delete 2>/dev/null || true
	@echo "Arquivos cifrados, recuperados e resultados removidos."

clean-all: clean clean-generated

limpar: clean-all

-include $(DEPENDENCIES)
