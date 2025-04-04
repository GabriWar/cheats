export LD_LIBRARY_PATH=$PWD/libLIN
g++ -std=c++20 -I includeLIN/libmem/ -L libLIN/ -llibmem -o test test.cpp
if [ $? -ne 0 ]; then
    echo "Build failed."
    exit 1
fi
chmod +x test
#invoke passing arguments passed to the script
./test $@