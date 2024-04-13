/** netmill
2022, Simon Zolin */

package com.github.stsaz.netmill;

import android.content.Context;
import android.util.Log;

class Core extends UtilAndroid {
	private static final String TAG = "netmill.Core";

	private static Core instance;
	private int refcount;

	NetMillAndroid nml;

	private boolean init(Context ctx) {
		UtilAndroid.TAG = "netmill.Util";

		nml = new NetMillAndroid();
		nml.init();
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

	@Override
	void errlog(String mod, String fmt, Object... args) {
		Log.e(mod, String.format("%s: %s", mod, String.format(fmt, args)));
	}

	void dbglog(String mod, String fmt, Object... args) {
		if (BuildConfig.DEBUG)
			Log.d(mod, String.format("%s: %s", mod, String.format(fmt, args)));
	}
}
