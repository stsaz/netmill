# netmill Build Instructions

## Step 1. Download code

```sh
mkdir netmill-src
cd netmill-src
git clone https://github.com/stsaz/ffbase
git clone https://github.com/stsaz/ffos
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
make -j8 OS=windows COMPILER=gcc CROSS_PREFIX=x86_64-w64-mingw32-
```

* Cross-Build on Linux for Android:

```sh
make -j8 -C android SDK_DIR=$SDK_DIR
```

* Build on FreeBSD:

```sh
gmake -j8
```

* Build docker-container:

```sh
bash docker.sh create
bash docker.sh start &
bash docker.sh ..
```

* Build inside a separate directory:

```sh
mkdir netmill/build
cd netmill/build
make -j8 -f ../../netmill/Makefile ROOT_DIR=../..
```

`netmill-0` is an application directory.
