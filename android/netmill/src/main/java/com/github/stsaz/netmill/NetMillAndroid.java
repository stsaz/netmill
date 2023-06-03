package com.github.stsaz.netmill;

class NetMillAndroid {
	
	private NetMill nml;

	boolean http_server_active;
	String status;

	void init() {
		nml = new NetMill();
		nml.log_android = true;
		nml.init();
	}

	void destroy() {
		if (http_server_active)
			nml.httpStop();
		nml.destroy();
	}

	int httpStart() {
		nml.port = 8080;
		nml.proxy = true;
		int r = nml.httpStart();
		status = String.format("Proxy server is listening on port %d", nml.port);
		http_server_active = true;
		if (r != 0) {
			status = String.format("Couldn't start proxy server: %s", nml.error);
			http_server_active = false;
		}
		return r;
	}

	void httpStop() {
		nml.httpStop();
		http_server_active = false;
	}
}
