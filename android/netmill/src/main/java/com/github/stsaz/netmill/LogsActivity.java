/** netmill/Android: logs
2026, Simon Zolin */

package com.github.stsaz.netmill;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SearchView;
import androidx.recyclerview.widget.LinearLayoutManager;

import android.os.Bundle;

import com.github.stsaz.netmill.databinding.LogsBinding;

public class LogsActivity extends AppCompatActivity {
	private static final String TAG = "netmill.LogsActivity";
	Core core;
	private LogsBinding b;
	private ViewAdapter view_adapter;
	private Core.CoreTimer update_timer;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		b = LogsBinding.inflate(getLayoutInflater());
		setContentView(b.getRoot());

		core = Core.ref();
		core.nml.logsOnChanged(() -> {
				view_adapter.on_change(0, -1);
			});
		view_adapter = new ViewAdapter(core, this, new ViewHolder.Parent() {
				public int count() {
					return core.nml.nml.logRows();
				}

				public String display_line(int i) {
					String[] rows = core.nml.nml.logDisplay(i, 1);
					return rows[0];
				}

				public void on_click(int i) { row_on_click(i); }

				public void on_longclick(int i) {
				}
			});
		b.view.setLayoutManager(new LinearLayoutManager(this));
		b.view.setAdapter(view_adapter);
		b.view.setItemAnimator(null);
		update_timer = core.timer(2000, () -> {
				view_adapter.on_change(0, -1);
			});

		b.tFilter.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
			public boolean onQueryTextSubmit(String query) {
				return true;
			}

			public boolean onQueryTextChange(String newText) {
				core.nml.nml.logsFilter(newText);
				view_adapter.on_change(0, -1);
				return true;
			}
		});
	}

	@Override
	protected void onDestroy() {
		core.timer_stop(update_timer);
		core.nml.logsOnChanged(null);
		core.nml.nml.logsFilter("");
		core.unref();
		super.onDestroy();
	}

	private void row_on_click(int i) {
		String host = core.nml.nml.logHost(i);
		core.nml.nml.hostsAdd(host, 0);
		core.gui.msg_show(this, String.format("Added %s to block-list", host));
	}
}
