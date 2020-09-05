all:
	c++ -O3 -Wall -shared -std=c++11 -fPIC `python3 -m pybind11 --includes` -I../src ../src/crypto/sha3.cpp sha3_sipa.cpp -o sha3_sipa`python3-config --extension-suffix`

clean:
	rm -f *`python3-config --extension-suffix`
