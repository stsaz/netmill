/** netmill/Android: GUI
2026, Simon Zolin */

package com.github.stsaz.netmill;

import android.content.Context;
import android.widget.Toast;

class GUI {
	static void msg_show(Context ctx, String fmt, Object... args) {
		Toast.makeText(ctx, String.format(fmt, args), Toast.LENGTH_SHORT).show();
	}
}
