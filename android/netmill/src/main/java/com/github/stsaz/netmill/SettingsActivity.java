/** netmill/Android: settings
2023, Simon Zolin */

package com.github.stsaz.netmill;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import com.github.stsaz.netmill.databinding.ActivitySettingsBinding;

public class SettingsActivity extends AppCompatActivity {

	private ActivitySettingsBinding b;
	private Core core;
	private ExplorerMenu explorer;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		b = ActivitySettingsBinding.inflate(getLayoutInflater());
		setContentView(b.getRoot());

		core = Core.ref();
		explorer = new ExplorerMenu(core, this);
		b.eHttpLocalPath.setOnClickListener(v -> explorer.show(b.eHttpLocalPath, 0));
		load();
	}

	@Override
	protected void onPause() {
		save();
		super.onPause();
	}

	@Override
	protected void onDestroy() {
		core.unref();
		super.onDestroy();
	}

	private void load() {
		b.eHttpPort.setText(core.int_to_str(core.nml.http.port));
		b.swHttpLocal.setChecked(!core.nml.http.proxy);
		b.eHttpLocalPath.setText(core.nml.http.www_dir);
	}

	private void save() {
		core.nml.http.port = core.str_to_uint(b.eHttpPort.getText().toString(), core.nml.http.port);
		core.nml.http.proxy = !b.swHttpLocal.isChecked();
		core.nml.http.www_dir = b.eHttpLocalPath.getText().toString();
		core.nml.conf_normalize();
	}
}
