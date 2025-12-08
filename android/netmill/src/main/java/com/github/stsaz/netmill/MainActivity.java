/** netmill
2023, Simon Zolin */

package com.github.stsaz.netmill;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.Manifest;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuItem;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import com.github.stsaz.netmill.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

	private ActivityMainBinding binding;
	private Core core;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		binding = ActivityMainBinding.inflate(getLayoutInflater());
		setContentView(binding.getRoot());

		setSupportActionBar(binding.toolbar);

		binding.buttonStart.setOnClickListener((v) -> server_start_stop());

		core = Core.init_once(this);
		update();
		init_system();
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
		} else if (id == R.id.action_about) {
			startActivity(new Intent(this, AboutActivity.class));
		} else {
			return super.onOptionsItemSelected(item);
		}
		return true;
	}

	/** Process the result of requestPermissions() */
	public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
		super.onRequestPermissionsResult(requestCode, permissions, grantResults);
	}

	/** Process the result of startActivityForResult() */
	public void onActivityResult(int requestCode, int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode, data);
	}

	private static final int REQUEST_PERM_READ_STORAGE = 1;
	private static final int REQUEST_STORAGE_ACCESS = 1;

	/** Request system permissions */
	private void init_system() {
		String[] perms = new String[]{
			Manifest.permission.READ_EXTERNAL_STORAGE,
			Manifest.permission.WRITE_EXTERNAL_STORAGE,
		};
		for (String p : perms) {
			if (ActivityCompat.checkSelfPermission(this, p) != PackageManager.PERMISSION_GRANTED) {
				ActivityCompat.requestPermissions(this, perms, REQUEST_PERM_READ_STORAGE);
				break;
			}
		}

		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
			if (!Environment.isExternalStorageManager()) {
				Intent it = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
					Uri.parse("package:" + BuildConfig.APPLICATION_ID));
				ActivityCompat.startActivityForResult(this, it, REQUEST_STORAGE_ACCESS, null);
			}
		}
	}

	private void update() {
		binding.textviewStatus.setText(core.nml.status);

		String s = getString(R.string.b_start);
		if (core.nml.http_server_active)
			s = "Stop";
		binding.buttonStart.setText(s);
	}

	private void server_start_stop() {
		if (core.nml.http_server_active) {
			core.nml.httpStop();
			core.nml.status = "";
			update();
			stopService(new Intent(this, Svc.class));
			return;
		}

		int r = core.nml.httpStart();
		update();
		if (r == 0) {
			startService(new Intent(this, Svc.class));
		}
	}
}
