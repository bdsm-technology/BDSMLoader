all: bdsm.loader

bdsm.loader: main.cpp dep.cpp dep.h coreclrhost.h
	clang++ -std=c++2a -O3 -flto -shared -fPIC main.cpp dep.cpp -o $@ -L . -ldl -lstdc++fs -fvisibility=hidden -Wall -Werror -Wno-return-type-c-linkage
	patchelf --add-needed libcoreclr.so $@
	# strip $@

clean:
	-rm bdsm.loader