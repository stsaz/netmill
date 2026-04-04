/** netmill/Android: hosts
2026, Simon Zolin */

package com.github.stsaz.netmill;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;

import android.os.Bundle;

import com.github.stsaz.netmill.databinding.HostsBinding;

public class HostsActivity extends AppCompatActivity {
	private static final String TAG = "netmill.HostsActivity";
	Core core;
	private HostsBinding b;
	private ViewAdapter view_adapter;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		b = HostsBinding.inflate(getLayoutInflater());
		setContentView(b.getRoot());

		core = Core.ref();
		view_adapter = new ViewAdapter(core, this, new ViewHolder.Parent() {
				public int count() {
					return core.nml.nml.hostsRows();
				}

				public String display_line(int i) {
					String[] rows = core.nml.nml.hostsDisplay(i, 1);
					return rows[0];
				}

				public void on_click(int i) {
				}

				public void on_longclick(int i) { row_on_lclick(i); }
			});
		b.view.setLayoutManager(new LinearLayoutManager(this));
		b.view.setAdapter(view_adapter);
		b.view.setItemAnimator(null);
	}

	@Override
	protected void onDestroy() {
		core.unref();
		super.onDestroy();
	}

	private void row_on_lclick(int i) {
		core.nml.nml.hostsRm(i, 0);
		core.gui.msg_show(this, String.format("Removed 1 host from block-list"));
		view_adapter.on_change(0, -1);
	}
}
