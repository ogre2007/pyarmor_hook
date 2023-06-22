#include "py_incl.h"
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pyarmor_hook.h"
#include "re_mprot.h"

static void _libhook_init() __attribute__((constructor));
static void _libhook_init() { printf("[*] Hook actviated.\n"); }

#define CHACHA_ENTRY 0x24A110 // 0x326510
#define LIBCRYPTO_ENTRY 0x973B0
#define CO_FOLDER "./co_marshaled/"

void hexdump(const void *data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
}

void init_python_functions() {
  if (LIBPYTHON_INITED)
    return;
  if (!PyFrame_GetCode_My) {
    PyFrame_GetCode_My = dlsym(REAL_LIBC, "PyFrame_GetCode");
  }
  if (!PyMarshal_WriteObjectToFile_My) {
    PyMarshal_WriteObjectToFile_My =
        dlsym(REAL_LIBC, "PyMarshal_WriteObjectToFile");
  }
  if (!PyObject_Print_My) {
    PyObject_Print_My = (int (*)(PyObject * o, FILE * fp, int flags))
        dlsym(REAL_LIBC, "PyObject_Print");
  }
  if (!PyObject_Repr_My) {
    PyObject_Repr_My = dlsym(REAL_LIBC, "PyObject_Repr");
  }
  if (!PyObject_Str_My) {
    PyObject_Str_My = dlsym(REAL_LIBC, "PyObject_Str");
  }
  if (!PyObject_Bytes_My) {
    PyObject_Bytes_My = dlsym(REAL_LIBC, "PyObject_Bytes");
  }
  if (!PyObject_ASCII_My) {
    PyObject_ASCII_My = dlsym(REAL_LIBC, "PyObject_ASCII");
  }
  if (!PyBytes_AsString_My) {
    PyBytes_AsString_My = dlsym(REAL_LIBC, "PyBytes_AsString");
  }

  if (!PyObject_Type_My) {
    PyObject_Type_My = dlsym(REAL_LIBC, "PyObject_Type");
  }
  if (!PyThreadState_Get_My) {
    PyThreadState_Get_My = dlsym(REAL_LIBC, "PyThreadState_Get");
  }
  if (!PyObject_IsTrue_My) {
    PyObject_IsTrue_My =
        (int (*)(PyObject *))dlsym(REAL_LIBC, "PyObject_IsTrue");
  }
  if (!PyEval_EvalCode_My)
    PyEval_EvalCode_My = (PyObject * (*)(PyCodeObject *, void *, void *))
        dlsym(REAL_LIBC, "PyEval_EvalCode");
  if (!_PyArg_VaParseTupleAndKeywords) {
    _PyArg_VaParseTupleAndKeywords =
        dlsym(REAL_LIBC, "PyArg_VaParseTupleAndKeywords");
  }
  if (!_PyArg_VaParse) {
    _PyArg_VaParse = dlsym(REAL_LIBC, "PyArg_VaParse");
  }

  if (!__PyBytes_FromStringAndSize) {
    __PyBytes_FromStringAndSize = dlsym(REAL_LIBC, "PyBytes_FromStringAndSize");
  }
  if (!__Py_CheckFunctionResult) {
    __Py_CheckFunctionResult = dlsym(REAL_LIBC, "_Py_CheckFunctionResult");
  }

  LIBPYTHON_INITED = 1;
}

PyObject *PyBytes_FromStringAndSize_(const char *v, Py_ssize_t len) {
  init_python_functions();
  // printf("%p\n", v);
  char searchee[] = {0x33, 0xEB, 0xD6, 0x9A};
  if (v && len > 10 && memmem(v, len, searchee, 4)) {
    hexdump(v, len > 0x100 ? len : len);
  }

  return __PyBytes_FromStringAndSize(v, len);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  if (!real_connect) {
    real_connect = dlsym(REAL_LIBC, "connect");
  }
  struct sockaddr_in *addr_in = addr;
  char *ip = inet_ntoa(addr_in->sin_addr);
  int result = -1;
  return result;
}

static int check_ptr(const void *ptr) {
  // printf("check_ptr ENTER\n");
  // int fd = open("/dev/null", O_WRONLY);
  // ptr = ((long long)ptr) & ~(getpagesize()-1);
  int ret = 0;
  // if (ptr>0x1000 && ((long long)ptr&0xFFFF000)!=0 && write(fd, ptr, 100) ==
  // 100) {
  if (has_mprotection(ptr, PROT_READ, PROT_READ)) {
    ret = 1;
  }
  // close(fd);
  // printf("check_ptr EXIT\n");
  return ret;
}

void print_repr(PyObject *obj) {
  init_python_functions();
  if (!check_ptr(obj) || !obj->ob_refcnt) {
    return;
  }
  PyObjectType *type = (PyObjectType *)obj->ob_type;
  if (!check_ptr(type)) {
    return;
  }
  const char *tp_name = type->tp_name;
  PyObject *repr = PyObject_Repr_My(obj);
  if (repr) {
    const char *bytes = ((PyBytesObject *)repr)->ob_sval;
    printf("%s", bytes);
    _Py_Dealloc(repr);
  } else {
    printf("Unreprable\n");
  }
  printf("\n");
}

int PyArg_ParseTuple_(PyObject *args, const char *format, ...) {
  init_python_functions();

  // if (!strcmp(format, "On:scan_once")){
  if (!strcmp(format, "On|i:scanstring")) {
    printf("%s\n", format);
    print_repr(args);
  }
  va_list vargs;
  va_start(vargs, format);
  int ret = _PyArg_VaParse(args, format, vargs);
  va_end(vargs);
  return ret;
}

int PyArg_ParseTupleAndKeywords_(PyObject *args, PyObject *kw,
                                 const char *format, char *keywords[], ...) {
  init_python_functions();

  // if (!strcmp(format, "On:scan_once")){
  printf("%s\n", format);
  print_repr(args);
  print_repr(kw);
  va_list vargs, vargs_copy;
  va_start(vargs, keywords);
  va_copy(vargs_copy, vargs);

  int ret = _PyArg_VaParseTupleAndKeywords(args, kw, format, keywords, vargs);
  /*
  for (int i =0 ; keywords[i]; i++) {
    printf("\narg:%s:\n", keywords[i]);
    PyObject * arg = va_arg(vargs_copy, PyObject*);
    //hexdump(arg,100);
    printf("%p\n", arg);
    print_repr(arg);
  }
  printf("EXIT_LOOP\n");*/
  va_end(vargs);

  va_end(vargs_copy);
  return ret;
}

static void dump_stack(PyFrameObject *frame) {
  init_python_functions();
  if (!check_ptr(frame)) {
    printf("no frame");
    return;
  }

  if (!check_ptr(frame->f_valuestack) && !check_ptr(frame->f_stacktop)) {
    printf("no stack: ");
    printf("%p %p %p\n", frame, frame->f_valuestack, frame->f_stacktop);
    return;
  }
  printf("%p %p %p\n", frame, frame->f_valuestack, frame->f_stacktop);

  PyObject **sp = frame->f_stacktop;
  int size = frame->f_code->co_stacksize;
  int i = 0;
  printf("\nstack(%p-%p, %d)=[\n", frame->f_stacktop, frame->f_valuestack,
         size);

  for (PyObject **ptr = sp; i < size; ptr--, i++) {
    // if (ptr != stack_base) {
    printf(", <");
    PyObject *obj = *ptr;

    if (check_ptr(obj)) {
      // printf("%p: %llx", obj, *(uint64_t*)obj);
      //  printf("OBJ ADDR =%p\n", obj);
      //  hexdump(obj, 30);
      PyObjectType *type = (PyObjectType *)obj->ob_type;
      // printf("TYPE ADR = %p\n", type);
      if (check_ptr(type)) {
        const char *tp_name = type->tp_name;
        // printf("typename_addr = %p\n", tp_name);
        if (check_ptr(tp_name) && strlen(tp_name) > 2 &&
            (strcmp(tp_name, "13'}"))) {
          // printf("%s: \n", tp_name);
          // printf("typename = %s\n", tp_name);
          if (strcmp(tp_name, "code"))
            print_repr(obj);
        }
        printf(">\n");
      }
    }
  }
  printf("]\n");
  fflush(stdout);
}

static PyObject *(*_PyInit_openssl)() = NULL;

int ends_with(const char *str, const char *suffix) {
  if (!str || !suffix)
    return 0;
  size_t lenstr = strlen(str);
  size_t lensuffix = strlen(suffix);
  if (lensuffix > lenstr)
    return 0;
  return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

void save_co(PyCodeObject *co, const char *filename) {
  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    perror("fopen: ");
    exit(-1);
  }
  PyMarshal_WriteObjectToFile_My((PyObject *)co, fp, 2);
  fclose(fp);
}

PyObject *get_real_consts(PyCodeObject *co) {
  unsigned long key = *(unsigned long *)(PYTRANSFORM_ADDRESS + 0x314FE8);
  return (PyObject *)((co->co_consts->ob_refcnt - 0x7F38) ^ key);
}

void repr_co(PyCodeObject *co) {
  printf("co_attrs: argcnt=%d, posonlyacnt:%d, kwonlyacnt:%d, nlocals:%d, "
         "stacksize:%d, flags:%d,fl:%d\n",
         co->co_argcount, co->co_posonlyargcount, co->co_kwonlyargcount,
         co->co_nlocals, co->co_stacksize, co->co_flags, co->co_firstlineno);
  printf("consts:\n");
  print_repr(co->co_consts);
  printf("\n");
  print_repr(co->co_names);
  print_repr(co->co_varnames);
  print_repr(co->co_freevars);
  print_repr(co->co_cellvars);
}

void filter_fname(char *src) {
  while (*src) {
    if (('a' <= *src && *src <= 'z') || ('0' <= *src && *src <= '9') ||
        ('A' <= *src && *src <= 'Z') || *src == '_' || *src == '/' ||
        *src == '.') {
    } else {
      *src = '_';
    }
    src++;
  }
}

void process_frame(PyFrameObject *frame, int save_code) {
  if (!check_ptr(frame)) {
    printf("bad frame.");
    return;
  }
  init_python_functions();
  static const size_t MAX_BUF_SZ = 0x80;
  char filename[MAX_BUF_SZ];
  char filename_locals[MAX_BUF_SZ];
  char filename_globals[MAX_BUF_SZ];

  PyObject *Py_None = dlsym(REAL_LIBC, "_Py_NoneStruct");
  if (!Py_None) {
    perror("dlsym pynone: ");
    exit(-1);
  }

  PyCodeObject *co = frame->f_code;
  snprintf(filename, MAX_BUF_SZ, "%s%s_%s_%04x", CO_FOLDER,
           (co->co_filename->ob_sval + 8), co->co_name->ob_sval, NUM);
  filter_fname(filename);
  printf("HOOKED %s\n", filename);

  PyObject *old_consts = co->co_consts;
  co->co_consts = get_real_consts(co);

  // repr_co(co);

  printf("\nframe_attrs:\nglobs:\n");
  // print_repr(frame->f_globals);
  printf("\nlocals:\n");
  print_repr(frame->f_locals);

  if (save_code) {
    save_co(co, filename);
  }

  co->co_consts = old_consts;
}

PyObject *_Py_CheckFunctionResult(PyObject *tstate, PyObject *callable,
                                  PyObject *result, const char *where) {
  init_python_functions();

  if (__builtin_return_address(0) == (void *)PYTRANSFORM_ADDRESS + 0x9B3F) {
    if (tstate) {
      printf("HOOKED EXIT:\n");
      process_frame(*(PyFrameObject **)((uint64_t)tstate + 0x18), 0);

      // dump_stack((uint64_t)tstate + 0x18);
    } else {
      printf("NO TSTATE\n");
    }
    print_repr(result);
    printf("DUMPED %d\n", NUM++);
  }
  PyObject *ret = __Py_CheckFunctionResult(tstate, callable, result, where);

  return ret;
}

void *PyThreadState_Get(void) {
  init_python_functions();
  PyFrameObject *dst = 0;
  __asm__ __volatile__("mov %%rdi, %0" : "=r"(dst));
  void *result = PyThreadState_Get_My();
  if (PYTRANSFORM_ADDRESS) {
    void *retaddr = __builtin_return_address(0);
    if (retaddr == (void *)PYTRANSFORM_ADDRESS + PYTRANSFORM_INTERP_HOOK) {
      // process_frame(dst, 1);
      dump_stack(dst);
    }
  }
  return result;
}

void *dlopen(const char *fname, int flag) {
  if (!real_dlopen) {
    real_dlopen = dlsym(REAL_LIBC, "dlopen");
  }
  void *result = real_dlopen(fname, flag);
  if (fname) {
    printf("%.*s\n", 256, fname);
    struct link_map *lm = (struct link_map *)result;
    if (ends_with(fname, "pytransform.so")) {

      printf("PYTRANSFORM LOADED at 0x%lx\n", lm->l_addr);

      PYTRANSFORM_ADDRESS = lm->l_addr;

    } else if (ends_with(fname, "_openssl.abi3.so")) {

      // set_sw_break(lm->l_addr + 0x24A110  , 1*getpagesize());
    } else if (ends_with(fname, "libcrypto.so.1.0.0")) {
      // set_sw_break(lm->l_addr + LIBCRYPTO_ENTRY);
    } else if (ends_with(fname, "_json.cpython-39-x86_64-linux-gnu.so")) {
      // set_sw_break(lm->l_addr + 0x60B0 , 1);
    }
  }

  // if(!strcmp(fname, "pytransform.so")) {
  //  raise(SIGTRAP);
  // }
  return result;
}

PyObject *PyEval_EvalCodee(PyCodeObject *co, void *globals, void *locals) {
  init_python_functions();

  PyFrameObject *dst = (PyFrameObject *)PyEval_GetFrame();
  if (check_ptr(dst)) {
    printf("\n[*][%d]Hooked state aquisition from normal interpreter. Frame "
           "(r13):%p\n",
           NUM++, (void *)dst);
    if (dst->f_code) {
      printf("co: %s %s\n", dst->f_code->co_filename->ob_sval,
             dst->f_code->co_name->ob_sval);

    } else {
      printf("no f_code");
      exit(-1);
    }
    // process_frame(dst);
    // dump_stack(dst);
  }
  return PyEval_EvalCode_My(co, globals, locals);
}