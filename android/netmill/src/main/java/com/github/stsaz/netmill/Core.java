/** netmill/Android
2022, Simon Zolin */

package com.github.stsaz.netmill;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;

import androidx.core.app.ActivityCompat;

import java.util.Timer;
import java.util.TimerTask;

class Core extends UtilAndroid {
	private static final String TAG = "netmill.Core";
	private static final String CONF_FN = "netmill-user.conf";
	private static final String CONF_DIR = "/storage/emulated/0/netmill";

	private static Core instance;
	private int refcount;

	NetMillAndroid nml;
	UtilNative util;
	GUI gui;
	private Conf conf;
	private String work_dir;
	String[] storage_paths;
	private Handler tq;

	private boolean init(Context ctx) {
		UtilAndroid.TAG = "netmill.Util";
		work_dir = ctx.getFilesDir().getPath();
		storage_paths = system_storage_dirs(ctx);
		dir_make(CONF_DIR);

		tq = new Handler(Looper.getMainLooper());

		nml = new NetMillAndroid();
		util = new UtilNative();
		gui = new GUI();
		conf = new Conf();
		nml.init(ctx.getApplicationInfo().nativeLibraryDir);
		nml.http.block_hosts_f = CONF_DIR + "/block.txt";
		conf_load();
		return true;
	}

	void unref() {
		instance.dbglog(TAG, "unref");
		refcount--;
		if (refcount == 0) {
			nml.destroy();
		}
	}

	static Core ref() {
		instance.dbglog(TAG, "ref");
		instance.refcount++;
		return instance;
	}

	static Core init_once(Context ctx) {
		if (instance == null) {
			Core c = new Core();
			if (!c.init(ctx))
				return null;
			instance = c;
		}

		return ref();
	}

	boolean sys_permisson_request(Activity activity, String[] perms, int code, int ext_stg_mgr_req_code) {
		boolean r = true;

		for (String p : perms) {
			if (ActivityCompat.checkSelfPermission(activity, p) != PackageManager.PERMISSION_GRANTED) {
				ActivityCompat.requestPermissions(activity, perms, code);
				r = false;
				break;
			}
		}

		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
			if (ext_stg_mgr_req_code != 0 && !Environment.isExternalStorageManager()) {
				Intent it = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + BuildConfig.APPLICATION_ID));
				ActivityCompat.startActivityForResult(activity, it, ext_stg_mgr_req_code, null);
				r = false;
			}
		}

		return r;
	}

	private String conf_file_name() { return work_dir + "/" + CONF_FN; }

	void conf_load() {
		if (conf.confRead(conf_file_name())) {
			conf_http_read(conf);
		}
		nml.conf_normalize();
	}

	void conf_save() {
		StringBuilder sb = new StringBuilder();
		sb.append(conf_http_write());
		dbglog(TAG, "%s", sb.toString());
		conf.confWrite(conf_file_name(), sb.toString().getBytes());
	}

	private void conf_http_read(Conf conf) {
		nml.http.proxy = conf.enabled(Conf.HTTP_PROXY);
		nml.http.port = conf.number(Conf.HTTP_PORT);
		nml.http.www_dir = conf.value(Conf.HTTP_WWW_DIR);
	}

	private String conf_http_write() {
		return String.format(
			"http_proxy %d\n"
			+ "http_port %d\n"
			+ "http_www_dir %s\n"
			, (nml.http.proxy) ? 1 : 0
			, nml.http.port
			, nml.http.www_dir
			);
	}

	static class CoreTimer {
		Timer t;
	}

	interface TimerFunc {
		void run();
	}

	CoreTimer timer(int period_msec, TimerFunc cb) {
		CoreTimer t = new CoreTimer();
		t.t = new Timer();
		t.t.schedule(new TimerTask() {
				public void run() {
					tq.post(() -> cb.run());
				}
			}, period_msec, period_msec);
		return t;
	}

	void timer_stop(CoreTimer t) {
		t.t.cancel();
		t.t = null;
	}

	@Override
	void errlog(String mod, String fmt, Object... args) {
		Log.e(mod, String.format("%s: %s", mod, String.format(fmt, args)));
	}

	void dbglog(String mod, String fmt, Object... args) {
		if (BuildConfig.DEBUG)
			Log.d(mod, String.format("%s: %s", mod, String.format(fmt, args)));
	}
}
