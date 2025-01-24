CXX := g++
SOURCE := src/frontend.cpp src/tools.cpp
TARGET := frontend
FLAGS := -Wall -g
BIN := bin

all: $(BIN)/$(TARGET)

$(BIN)/$(TARGET): $(SOURCE)
	mkdir -p $(BIN)
	$(CXX) $(FLAGS) $(SOURCE) -std=c++11 -o $(BIN)/$(TARGET)

clean:
	-rm -f $(BIN)/$(TARGET)

.PHONY: all clean
