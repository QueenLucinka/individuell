CXX = g++
CXXFLAGS = -std=c++11 -Wall
LDFLAGS = -lssl -lcrypto

SRC = main.cpp 
OBJ = $(SRC:.cpp=.o)
TARGET = my_program

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
