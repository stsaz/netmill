/** netmill/Android
2024, Simon Zolin */

package com.github.stsaz.netmill;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;

import com.github.stsaz.netmill.databinding.AboutBinding;

public class AboutActivity extends AppCompatActivity {
	private static final String TAG = "netmill.AboutActivity";
	Core core;
	private AboutBinding b;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		b = AboutBinding.inflate(getLayoutInflater());
		setContentView(b.getRoot());

		core = Core.ref();

		b.lAbout.setText(String.format("v%s\n\n%s",
			core.nml.nml.version(),
			"https://github.com/stsaz/netmill"));
	}

	@Override
	protected void onDestroy() {
		super.onDestroy();
	}
}
