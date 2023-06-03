/** netmill: JNI
2023, Simon Zolin */

package com.github.stsaz.netmill;

class NetMill {
	boolean log_android;
	boolean log_debug;
	long log_fd = -1;
	public native void init();
	long ctx;

	native void destroy();

	int port = 8080;
	boolean proxy;
	String www_dir = "";
	native int httpStart();

	native int httpStop();

	String error = "";

	static {
		System.loadLibrary("netmill");
	}
}
