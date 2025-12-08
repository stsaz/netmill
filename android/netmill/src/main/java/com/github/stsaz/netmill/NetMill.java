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

	native String version();

	static class HttpServerOptions {
		int port = 8080;
		int workers = 1;
		int io_workers = 1; // 0: don't use separate I/O threads
		boolean proxy = true;
		String www_dir = "";
		String error = "";
	}
	native int httpStart(HttpServerOptions hso);

	native int httpStop();

	native String[] listIPAddresses();

	static {
		System.loadLibrary("netmill");
	}
}
