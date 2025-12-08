/** netmill
2023, Simon Zolin */

package com.github.stsaz.netmill;

class NetMillAndroid {

	NetMill nml;

	NetMill.HttpServerOptions http;
	boolean http_server_active;
	String status;

	void init() {
		nml = new NetMill();
		nml.log_android = true;
		nml.init();

		http = new NetMill.HttpServerOptions();
		http.workers = 2;
		http.io_workers = 2;
		http.port = 8080;
		http.proxy = true;
		http.www_dir = "/storage/emulated/0/Documents";
	}

	void destroy() {
		if (http_server_active)
			nml.httpStop();
		nml.destroy();
	}

	int httpStart() {
		int r = nml.httpStart(http);
		if (r != 0) {
			status = String.format("Couldn't start proxy server: %s", http.error);
			http_server_active = false;
			return r;
		}

		StringBuilder s = new StringBuilder();
		s.append(String.format("Proxy server is listening on port %d.\nAddresses:\n", http.port));
		String[] ips = nml.listIPAddresses();
		for (String ip : ips) {
			s.append(String.format("%s\n", ip));
		}
		status = s.toString();

		http_server_active = true;
		return r;
	}

	void httpStop() {
		nml.httpStop();
		http_server_active = false;
	}
}
