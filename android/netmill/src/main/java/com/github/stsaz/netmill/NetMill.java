/** netmill: JNI
2023, Simon Zolin */

package com.github.stsaz.netmill;

class NetMill {
	NetMill(String libdir) {
		System.load(String.format("%s/libnetmill.so", libdir));
	}

	boolean log_android; // write logs to Android
	boolean log_debug; // write debug logs
	// int log_fd = -1;
	public native void init();

	native void destroy();

	native String version();

	static final int IP_NOLOCAL = 1;
	native String[] listIPAddresses(int flags);

	static class HttpServerOptions {
		int port = 8080;
		int workers = 1;
		int io_workers = 1; // 0: don't use separate I/O threads
		boolean proxy = true;
		String block_hosts_f = "";
		String www_dir = "";
		String error = "";
	}
	native int httpStart(HttpServerOptions hso);

	native void httpStop();

	static class HttpStats {
		int received_kb, sent_kb;
	}
	native HttpStats httpStats();

	native int logRows();
	native void logsFilter(String filter);
	native String[] logDisplay(int i, int n);
	native String logHost(int i);

	native void hostsAdd(String host, int flags);
	native void hostsRm(int i, int flags);
	native void hostsStore(String filename);
	native int hostsRows();
	native String[] hostsDisplay(int i, int n);
}
