/** netmill/Android
2023, Simon Zolin */

package com.github.stsaz.netmill;

class NetMillAndroid {

	NetMill nml;

	NetMill.HttpServerOptions http;
	boolean http_server_active;
	String status;

	void init(String libdir) {
		nml = new NetMill(libdir);
		nml.log_android = true;
		nml.log_debug = false;
		nml.init();

		http = new NetMill.HttpServerOptions();
		http.workers = 2;
		http.io_workers = 2;
		http.port = 8080;
		http.proxy = true;
		http.www_dir = "/storage/emulated/0/Documents";
	}

	void destroy() {
		if (http_server_active) {
			nml.hostsStore(http.block_hosts_f);
			nml.httpStop();
		}
		nml.destroy();
	}

	void conf_normalize() {
	}

	int http_start() {
		int r = nml.httpStart(http);
		if (r != 0) {
			status = String.format("Couldn't start proxy server: %s", http.error);
			http_server_active = false;
			return r;
		}

		StringBuilder s = new StringBuilder();
		s.append(String.format("Proxy server is listening on port %d.\nAddresses:\n", http.port));
		String[] ips = nml.listIPAddresses(NetMill.IP_NOLOCAL);
		for (String ip : ips) {
			s.append(String.format("%s\n", ip));
		}
		status = s.toString();

		http_server_active = true;
		return r;
	}

	void http_stop() {
		nml.hostsStore(http.block_hosts_f);
		nml.httpStop();
		http_server_active = false;
	}

	interface LogsChanged {
		void changed();
	}
	void logsOnChanged(LogsChanged cb) {}
}
