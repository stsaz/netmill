package com.github.stsaz.netmill;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import com.github.stsaz.netmill.databinding.ActivitySettingsBinding;

public class SettingsActivity extends AppCompatActivity {

	private ActivitySettingsBinding binding;
	private Core core;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		binding = ActivitySettingsBinding.inflate(getLayoutInflater());
		setContentView(binding.getRoot());

		core = Core.ref();
		load();
	}

	@Override
	protected void onPause() {
		save();
		super.onPause();
	}

	private void load() {
		binding.eHttpPort.setText(core.int_to_str(core.nml.http.port));
		binding.swHttpLocal.setChecked(!core.nml.http.proxy);
		binding.eHttpLocalPath.setText(core.nml.http.www_dir);
	}

	private void save() {
		core.nml.http.port = core.str_to_uint(binding.eHttpPort.getText().toString(), core.nml.http.port);
		core.nml.http.proxy = !binding.swHttpLocal.isChecked();
		core.nml.http.www_dir = binding.eHttpLocalPath.getText().toString();
	}
}
