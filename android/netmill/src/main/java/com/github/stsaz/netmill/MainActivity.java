package com.github.stsaz.netmill;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import android.view.View;

import com.github.stsaz.netmill.databinding.ActivityMainBinding;

import android.view.Menu;
import android.view.MenuItem;

public class MainActivity extends AppCompatActivity {

	private ActivityMainBinding binding;
	private NetMillAndroid nml;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		binding = ActivityMainBinding.inflate(getLayoutInflater());
		setContentView(binding.getRoot());

		setSupportActionBar(binding.toolbar);

		binding.buttonStart.setOnClickListener((v) -> server_start());

		nml = new NetMillAndroid();
		nml.init();
	}

	@Override
	public void onDestroy() {
		nml.destroy();
		super.onDestroy();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.menu_main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();

		//noinspection SimplifiableIfStatement
		if (id == R.id.action_settings) {
			return true;
		}

		return super.onOptionsItemSelected(item);
	}

	private void server_start() {
		if (nml.http_server_active) {
			nml.httpStop();
			binding.buttonStart.setText("Start");
			binding.textviewStatus.setText("");
			return;
		}

		int r = nml.httpStart();
		binding.textviewStatus.setText(nml.status);
		if (r == 0) {
			binding.buttonStart.setText("Stop");
		}
	}
}
