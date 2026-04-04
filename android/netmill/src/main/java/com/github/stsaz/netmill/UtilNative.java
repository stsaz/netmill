/** netmill/Android: utils
2024, Simon Zolin */

package com.github.stsaz.netmill;

class UtilNative {
	static class Files {
		String[] display_rows;
		String[] file_names;
		int n_directories;
	}
	native Files dirList(String path, int flags);
}
