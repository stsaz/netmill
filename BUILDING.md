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

## Step 2. Cross-Build

* Cross-Build on Linux for Debian-bookworm:

	```sh
	bash xbuild-debianbookworm.sh
	```

* Cross-Build on Linux for Windows:

	```sh
	bash xbuild-win64.sh
	```

* Cross-Build on Linux for Alpine:

	```sh
	bash xbuild-alpine.sh
	```

* Cross-Build on Linux for Android:

	```sh
	make -j8 -C android SDK_DIR=$SDK_DIR
	```

## Step 2 (Option 2). Native Build

* Build on Linux:

	```sh
	make -j8
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

## Step 3. Use

`netmill-0` is the application directory.
