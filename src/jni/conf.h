/** netmill/Android: conf
2023, Simon Zolin */

#include <ffsys/file.h>

static const char setting_names[][20] = {
	"http_port",
	"http_proxy",
	"http_www_dir",
};

JNIEXPORT jboolean JNICALL
Java_com_github_stsaz_netmill_Conf_confRead(JNIEnv *env, jobject thiz, jstring jfilepath)
{
	int rc = 0;
	dbglog("%s: enter", __func__);
	const char *fn = jni_sz_js(jfilepath);
	ffvec d = {};
	if (fffile_readwhole(fn, &d, 1*1024*1024))
		goto end;
	jintArray jia = conf_read(env, *(ffstr*)&d, setting_names, FF_COUNT(setting_names), 0);

	jclass jc = jni_class_obj(thiz);
	jni_obj_jba_set(env, thiz, jni_field_jba(jc, "data"), *(ffstr*)&d);
	jni_obj_jo_set(thiz, jni_field(jc, "fields", JNI_TARR JNI_TINT), jia);
	rc = 1;

end:
	jni_sz_free(fn, jfilepath);
	ffvec_free(&d);
	dbglog("%s: exit", __func__);
	return rc;
}

JNIEXPORT jboolean JNICALL
Java_com_github_stsaz_netmill_Conf_confWrite(JNIEnv *env, jobject thiz, jstring jfilepath, jbyteArray jdata)
{
	dbglog("%s: enter", __func__);
	const char *fn = jni_sz_js(jfilepath);
	char *fn_tmp = ffsz_allocfmt("%s.tmp", fn);
	ffstr data = jni_str_jba(env, jdata);
	int rc = 0;
	if (fffile_writewhole(fn_tmp, data.ptr, data.len, 0)) {
		syserrlog("fffile_writewhole: %s", fn_tmp);
		goto end;
	}

	if (fffile_rename(fn_tmp, fn)) {
		syserrlog("fffile_rename: %s", fn);
		goto end;
	}
	rc = 1;

end:
	jni_bytes_free(data.ptr, jdata);
	jni_sz_free(fn, jfilepath);
	ffmem_free(fn_tmp);
	dbglog("%s: exit", __func__);
	return rc;
}
