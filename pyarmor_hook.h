
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1l)
#endif

#define REAL_LIBC RTLD_NEXT

typedef int request_t;

typedef void (*sighandler_t)(int);
int (*real_connect)(int sockfd, const void *addr, socklen_t addrlen) = NULL;

void *(*real_memcpy)(void *s1, const void *s2, size_t num) = NULL;
static FILE *DUMPSTER = NULL;
static const char DUMPSTER_NAME[] = "dumpster.pycode";
static const int VERSION = 0;
static const char DELIM[] = "********************************";

static PyObject *(*__Py_CheckFunctionResult)(PyObject *tstate,
                                             PyObject *callable,
                                             PyObject *result,
                                             const char *where) = NULL;

static PyObject *(*__PyBytes_FromStringAndSize)(const char *v,
                                                Py_ssize_t len) = NULL;

static int (*_PyArg_VaParse)(PyObject *args, const char *format,
                             va_list vargs) = NULL;

static int (*_PyArg_VaParseTupleAndKeywords)(PyObject *args, PyObject *kw,
                                             const char *format,
                                             char *keywords[],
                                             va_list vargs) = NULL;

static char *(*PyBytes_AS_STRING)(PyObject *string) = NULL;
static int (*PyObject_IsTrue_My)(PyObject *o) = NULL;

static void *(*real_dlopen)(const char *fname, int flag) = NULL;
static const char PYTRANSFORM_NAME[] = "pytransform.so";

static long long PYTRANSFORM_ADDRESS = 0;

static long long PYTRANSFORM_INTERP_HOOK = 0x91B0;

static PyObject *(*PyEval_EvalCode_My)(PyCodeObject *, void *, void *) = NULL;

typedef PyCodeObject *(*PyFrame_GetCode_t)(PyObject *);

static PyFrame_GetCode_t PyFrame_GetCode_My = NULL;

typedef void *(*PyMarshal_WriteObjectToFile_t)(PyObject *, FILE *, int);
static PyMarshal_WriteObjectToFile_t PyMarshal_WriteObjectToFile_My = NULL;

static PyObject *(*PyObject_Repr_My)(PyObject *) = NULL;
static PyObject *(*PyObject_Str_My)(PyObject *) = NULL;
static PyObject *(*PyObject_Bytes_My)(PyObject *) = NULL;
static const char *(*PyBytes_AsString_My)(PyObject *) = NULL;

static PyObject *(*PyObject_ASCII_My)(PyObject *) = NULL;
static PyObject *(*PyObject_Type_My)(PyObject *) = NULL;

static int (*PyObject_Print_My)(PyObject *o, FILE *fp, int flags) = NULL;

static void *(*PyThreadState_Get_My)() = NULL;

static int NUM = 0;

static int LIBPYTHON_INITED = 0;
