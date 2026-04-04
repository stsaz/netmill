/** netmill/Android: utils
2023, Simon Zolin */

#include <ffsys/path.h>
#include <ffsys/dir.h>
#include <ffsys/dirscan.h>

/** Read config data into Java array.
(KEY VALUE LF)... -> {value-offset value-length value-as-number}...
*/
jintArray conf_read(JNIEnv *env, ffstr data, const char settings[][20], uint n_settings, int int_default)
{
	const char *data_start = data.ptr;
	ffvec fields = {};
	ffvec_zalloc(&fields, n_settings * 3, 4);
	fields.len = n_settings * 3;
	int *dst = fields.ptr;

	while (data.len) {
		ffstr ln, k, v;
		ffstr_splitby(&data, '\n', &ln, &data);
		ffstr_splitby(&ln, ' ', &k, &v);

		int r = ffcharr_findsorted(settings, n_settings, sizeof(settings[0]), k.ptr, k.len);
		if (r < 0)
			continue;

		dst[r*3 + 0] = v.ptr - data_start;
		dst[r*3 + 1] = v.len;

		int n = int_default;
		ffstr_to_int32(&v, &n);
		dst[r*3 + 2] = n;
	}

	jintArray jia = jni_jia_vec(env, *(ffslice*)&fields);
	ffvec_free(&fields);
	return jia;
}

struct UtilNative_Files {
	jobjectArray display_rows;
	jobjectArray file_names;
	jint n_directories;
};

#define _I(name)  { #name, 'i', FF_OFF(struct UtilNative_Files, name), 0 }
#define _SA(name)  { #name, 'S', FF_OFF(struct UtilNative_Files, name), 0 }
static struct jni_cmap UtilNative_Files_map[] = {
	_SA(display_rows),
	_SA(file_names),
	_I(n_directories),
	{}
};
#undef _I
#undef _SA

JNIEXPORT jobject JNICALL
Java_com_github_stsaz_netmill_UtilNative_dirList(JNIEnv *env, jobject thiz, jstring jpath, jint flags)
{
	dbglog("%s: enter", __func__);
	const char *path = jni_sz_js(jpath);
	char *fullname = NULL, *fullname_name;
	size_t i = 0, n = 0;
	ffdirscanx dx = {};

	uint dsof = FFDIRSCANX_SORT_DIRS;

	if (!ffdirscanx_open(&dx, path, dsof))
		n = ffdirscan_count(&dx.ds);

	ffstr s_path = FFSTR_INITZ(path);
	fullname = ffmem_alloc(s_path.len + 1 + 255);
	ffmem_copy(fullname, s_path.ptr, s_path.len);
	fullname[s_path.len] = '/';
	fullname_name = fullname + s_path.len + 1;

	struct UtilNative_Files unf = {};
	jclass jcs = jni_class(JNI_CSTR);
	unf.file_names = jni_joa(n, jcs);
	unf.display_rows = jni_joa(n, jcs);

	const char *fn;
	while ((fn = ffdirscanx_next(&dx))) {
		uint off = *(uint*)((char*)dx.ds.names + dx.ds.cur - sizeof(uint));

		ffsz_copyz(fullname_name, 255, fn);
		jstring js = jni_js_sz(fullname);
		jni_joa_i_set(unf.file_names, i, js);
		jni_local_unref(js);

		if (off & 0x80000000) {
			js = jni_js_szf(env, "<DIR> %s", fn);
			unf.n_directories++;
		} else {
			js = jni_js_sz(fn);
		}
		jni_joa_i_set(unf.display_rows, i, js);
		jni_local_unref(js);

		i++;
	}

	jobject jo = jni_obj_new(x->UtilNative_Files.cls, x->UtilNative_Files.init);
	jni_obj_write(env, jo, x->UtilNative_Files.cls, UtilNative_Files_map, &unf);

	ffdirscanx_close(&dx);
	jni_sz_free(path, jpath);
	ffmem_free(fullname);
	dbglog("%s: exit", __func__);
	return jo;
}
