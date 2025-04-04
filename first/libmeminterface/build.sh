# filepath: /home/gabriwar/Desktop/gitthings/cheats/first/libmeminterface/build.sh

# Set the library path
export LD_LIBRARY_PATH="$PWD/LIBMEMLIN/libLIN:$LD_LIBRARY_PATH"

# Compile the program
g++ -std=c++20 -I LIBMEMLIN/includeLIN/libmem/ -L LIBMEMLIN/libLIN/ -llibmem -o test test.cpp
if [ $? -ne 0 ]; then
	echo "Build failed."
	exit 1
fi

# Make the output executable
chmod +x test

# Run the program with any arguments passed to the script
./test "$@"
