/** netmill
2023, Simon Zolin */

package com.github.stsaz.netmill;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import androidx.core.app.NotificationCompat;

public class Svc extends Service {
	private static final String TAG = "netmill.Svc";
	private Core core;

	private String notif_chan_create() {
		String nfy_chan = "";
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
			nfy_chan = "netmill.chan";
			NotificationManager mgr = (NotificationManager)getSystemService(NOTIFICATION_SERVICE);
			if (mgr != null) {
				NotificationChannel chan = new NotificationChannel(nfy_chan, "channame", NotificationManager.IMPORTANCE_LOW);
				mgr.createNotificationChannel(chan);
			}
		}
		return nfy_chan;
	}

	private Notification notif_create() {
		NotificationCompat.Builder nfy = new NotificationCompat.Builder(this, notif_chan_create())
			.setContentTitle("netmill")
			.setContentText("netmill")
			;
		return nfy.build();
	}

	@Override
	public void onCreate() {
		if (BuildConfig.DEBUG)
			Log.d(TAG, "onCreate");

		core = Core.ref();

		final int ID = 1;
		startForeground(ID, notif_create());
	}

	@Override
	public int onStartCommand(Intent intent, int flags, int startId) {
		core.dbglog(TAG, "onStartCommand");
		return START_NOT_STICKY;
	}

	@Override
	public IBinder onBind(Intent intent) { return null; }

	@Override
	public void onDestroy() {
		core.dbglog(TAG, "onDestroy");
		core.unref();
	}
}
