/** netmill/Android
2023, Simon Zolin */

package com.github.stsaz.netmill;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

class ViewHolder extends RecyclerView.ViewHolder
		implements View.OnClickListener, View.OnLongClickListener {

	final TextView text;

	interface Parent {
		int count();
		String display_line(int pos);
		void on_click(int i);
		void on_longclick(int i);
	}
	final Parent parent;

	ViewHolder(Parent parent, View itemView) {
		super(itemView);
		this.parent = parent;
		text = itemView.findViewById(R.id.view_row_text);
		itemView.setClickable(true);
		itemView.setOnClickListener(this);
		itemView.setOnLongClickListener(this);
	}

	public void onClick(View v) {
		parent.on_click(getAdapterPosition());
	}

	public boolean onLongClick(View v) {
		parent.on_longclick(getAdapterPosition());
		return true;
	}
}

class ViewAdapter extends RecyclerView.Adapter<ViewHolder> {
	private static final String TAG = "netmill.ViewAdapter";
	private final Core core;
	private final LayoutInflater inflater;
	private final ViewHolder.Parent parent;

	ViewAdapter(Core core, Context ctx, ViewHolder.Parent parent) {
		this.core = core;
		inflater = LayoutInflater.from(ctx);
		this.parent = parent;
	}

	@NonNull
	public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
		View v = inflater.inflate(R.layout.view_row, parent, false);
		return new ViewHolder(this.parent, v);
	}

	public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
		holder.text.setText(parent.display_line(position));
	}

	public int getItemCount() { return parent.count(); }

	void on_change(int how, int pos) {
		core.dbglog(TAG, "on_change: %d %d", how, pos);
		if (pos < 0)
			notifyDataSetChanged();
		// else if (how == UPDATE)
		// 	notifyItemChanged(pos);
		// else if (how == ADDED)
		// 	notifyItemInserted(pos);
		// else if (how == REMOVED)
		// 	notifyItemRemoved(pos);
	}
}
