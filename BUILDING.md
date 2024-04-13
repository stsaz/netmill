# netmill Build Instructions

## Step 1. Download code

```sh
mkdir netmill-src
cd netmill-src
git clone https://github.com/stsaz/ffbase
git clone https://github.com/stsaz/ffsys
git clone https://github.com/stsaz/ffpack
git clone https://github.com/stsaz/netmill
cd netmill
```

## Step 2. Build

* Build on Linux:

	```sh
	make -j8
	```

* Cross-Build on Linux for Windows:

	```sh
	sh xbuild-win64.sh
	```

* Cross-Build on Linux for Alpine:

	```sh
	sh xbuild-alpine.sh
	```

* Cross-Build on Linux for Android:

	```sh
	make -j8 -C android SDK_DIR=$SDK_DIR
	```

* Build on FreeBSD:

	```sh
	gmake -j8
	```

* Build inside a separate directory:

	```sh
	mkdir netmill/build
	cd netmill/build
	make -j8 -f ../../netmill/Makefile ROOT_DIR=../..
	```

`netmill-0` is an application directory.
