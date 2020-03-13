CXX		= g++
LIBS	= -lpcap

obj		= main.o \
          utils.o

exe		= sniffer

all: ${exe}

${exe}: ${obj}
	${CXX} $^ ${LIBS} -o $@

.SUFFIXES:
.SUFFIXES: .app .o
%.o:%.cpp
		$(CXX) -c $(CPPFLAGS) $(CXXFLAGS) $< -o $@

clean:
		-rm *.o ${exe}