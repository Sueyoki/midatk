all: dir_create server_test client_test utils_test mid_test arp_poison
ver = debug

ifeq ($(ver), release)
	CXXFLAGS := -std=c++2a -O3 -Wall
else
	CXXFLAGS := -std=c++2a -g -Wall
endif

LIBS := -lpthread -lcryptopp

# DIRS
OBJ_DIR := $(CURDIR)/build/Debug
OUT_DIR := $(CURDIR)/dist
INC_DIR := $(CURDIR)/include
TEST_DIR := $(CURDIR)/test
LOG_DIR := $(CURDIR)/log
SRC_DIR := $(CURDIR)/src

vpath %.o $(CURDIR)/build/Debug

INCS := protocol.h utils.h lengths.h msg_type.h
OBJS := server.o client.o server_test.o client_test.o mid_test.o mid_server.o protocol.o utils.o
TAGS := utils_test server_test client_test mid_test arp_poison

server_test: $(OBJ_DIR)/server_test.o $(OBJ_DIR)/server.o $(OBJ_DIR)/utils.o $(OBJ_DIR)/protocol.o
	$(CXX) $(CXXFLAGS) $^ -o $(OUT_DIR)/$@ $(LIBS)

client_test: $(OBJ_DIR)/client_test.o $(OBJ_DIR)/client.o $(OBJ_DIR)/utils.o $(OBJ_DIR)/protocol.o
	$(CXX) $(CXXFLAGS) $^ -o $(OUT_DIR)/$@ $(LIBS)

mid_test: $(OBJ_DIR)/mid_test.o $(OBJ_DIR)/server.o $(OBJ_DIR)/client.o \
$(OBJ_DIR)/mid_server.o $(OBJ_DIR)/utils.o $(OBJ_DIR)/protocol.o 
	$(CXX) $(CXXFLAGS) $^ -o $(OUT_DIR)/$@ $(LIBS)

utils_test: $(TEST_DIR)/utils_test.cpp $(OBJ_DIR)/utils.o
	$(CXX) $(CXXFLAGS) $^ -o $(OUT_DIR)/$@ -lcryptopp

arp_poison: $(TEST_DIR)/arp_poison.cpp
	$(CXX) $(CXXFLAGS) $< -o $(OUT_DIR)/$@ -lnet -lpcap

$(OBJ_DIR)/server_test.o: $(TEST_DIR)/server_test.cpp $(OBJ_DIR)/server.o 
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/client_test.o: $(TEST_DIR)/client_test.cpp $(OBJ_DIR)/client.o 
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/mid_test.o: $(TEST_DIR)/mid_test.cpp $(OBJ_DIR)/mid_server.o 
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/mid_server.o: $(SRC_DIR)/mid_server.cpp $(OBJ_DIR)/server.o $(OBJ_DIR)/client.o 
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/server.o: $(SRC_DIR)/server.cpp $(INC_DIR)/server.h $(addprefix $(INC_DIR)/,$(notdir $(INCS)))
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/client.o: $(SRC_DIR)/client.cpp $(INC_DIR)/client.h $(addprefix $(INC_DIR)/,$(notdir $(INCS)))
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/utils.o: $(SRC_DIR)/utils.cpp $(INC_DIR)/utils.h
	$(CXX) -c $(CXXFLAGS) $< -o $@

$(OBJ_DIR)/protocol.o: $(SRC_DIR)/protocol.cpp $(INC_DIR)/protocol.h
	$(CXX) -c $(CXXFLAGS) $< -o $@

# 创建目录函数
define CRT_DIR
	if [ ! -d $(1) ];\
	 	then\
    	mkdir -p $(1);\
	fi	
endef

.PHONY: dir_create clean all

# 用于创建一系列文件夹（如果文件夹不存在）
dir_create:  
	@$(call CRT_DIR,$(OUT_DIR))
	@$(call CRT_DIR,$(OBJ_DIR))
	@$(call CRT_DIR,$(TEST_DIR))
	@$(call CRT_DIR,$(LOG_DIR))

clean:
	$(RM) $(addprefix $(OUT_DIR)/,$(notdir $(TAGS)))
	$(RM) $(addprefix $(OBJ_DIR)/,$(notdir $(OBJS)))
	$(RM) -r $(LOG_DIR)