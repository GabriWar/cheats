export LD_LIBRARY_PATH=$PWD/lib
g++ -std=c++20 -I include/libmem/ -L lib/ -llibmem -o test test.cpp 
chmod +x test
#invoke passing arguments passed to the script
./test $@