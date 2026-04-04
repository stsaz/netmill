/** netmill/Android: main
2023, Simon Zolin */

package com.github.stsaz.netmill;

import android.content.Intent;
import android.Manifest;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import com.github.stsaz.netmill.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
	private static final String TAG = "netmill.MainActivity";
	private ActivityMainBinding b;
	private Core core;
	private Core.CoreTimer tmr;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		b = ActivityMainBinding.inflate(getLayoutInflater());
		setContentView(b.getRoot());

		setSupportActionBar(b.toolbar);

		b.bStart.setOnClickListener((v) -> server_start_stop());

		core = Core.init_once(this);
		update();
		init_system();
	}

	@Override
	protected void onStart() {
		super.onStart();
		core.dbglog(TAG, "onStart()");
	}

	@Override
	protected void onStop() {
		core.dbglog(TAG, "onStop()");
		core.conf_save();
		super.onStop();
	}

	@Override
	public void onDestroy() {
		core.unref();
		super.onDestroy();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			startActivity(new Intent(this, SettingsActivity.class));
		} else if (id == R.id.action_logs) {
			startActivity(new Intent(this, LogsActivity.class));
		} else if (id == R.id.action_hosts) {
			startActivity(new Intent(this, HostsActivity.class));
		} else if (id == R.id.action_about) {
			startActivity(new Intent(this, AboutActivity.class));
		} else {
			return super.onOptionsItemSelected(item);
		}
		return true;
	}

	private static final int REQUEST_PERM_READ_STORAGE = 1;

	/** Process the result of requestPermissions() */
	public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
		super.onRequestPermissionsResult(requestCode, permissions, grantResults);
	}

	private static final int REQUEST_STORAGE_ACCESS = 1;

	/** Process the result of startActivityForResult() */
	public void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
	}

	private void init_system() {
		final String[] perms = new String[]{
			Manifest.permission.READ_EXTERNAL_STORAGE,
			Manifest.permission.WRITE_EXTERNAL_STORAGE,
		};
		core.sys_permisson_request(this, perms, REQUEST_PERM_READ_STORAGE, REQUEST_STORAGE_ACCESS);
	}

	private void update() {
		b.lStatus.setText(core.nml.status);

		String s = getString(R.string.b_start);
		if (core.nml.http_server_active)
			s = "Stop";
		b.bStart.setText(s);

		if (core.nml.http_server_active) {
			tmr = core.timer(1000, () -> {
					NetMill.HttpStats hs = core.nml.nml.httpStats();
					b.lStat.setText(String.format("%dKB / %dKB"
						, hs.received_kb, hs.sent_kb));
				});
		} else {
			b.lStat.setText("");
		}
	}

	private void server_start_stop() {
		if (core.nml.http_server_active) {
			core.nml.http_stop();
			core.nml.status = "";
			core.timer_stop(tmr);
			tmr = null;
			update();
			stopService(new Intent(this, Svc.class));
			return;
		}

		int r = core.nml.http_start();
		update();
		if (r == 0) {
			startService(new Intent(this, Svc.class));
		}
	}
}
