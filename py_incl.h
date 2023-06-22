typedef ssize_t Py_ssize_t;
typedef struct _object {
  Py_ssize_t ob_refcnt;
  struct _object *ob_type;
} PyObject;

typedef struct _varobj {
  PyObject ob_base;
  Py_ssize_t ob_size;
} PyVarObject;

typedef struct {
  PyVarObject ob_base;

  Py_ssize_t ob_shash[3];
  char ob_sval[1];

  /* Invariants:
   *     ob_sval contains space for 'ob_size+1' elements.
   *     ob_sval[ob_size] == 0.
   *     ob_shash is the hash of the string or -1 if not computed yet.
   */
} PyBytesObject;

typedef struct _typeobject {
  PyVarObject ob_base;
  const char *tp_name; /* For printing, in format "<module>.<name>" */
  Py_ssize_t tp_basicsize, tp_itemsize; /* For allocation */
  long other;
} PyObjectType;

typedef struct pytry {
  int b_type;
  int b_handler;
  int b_level;
} PyTryBlock;

typedef struct __attribute__((aligned(4))) code_obj {
  PyObject ob_base;
  int co_argcount;
  int co_posonlyargcount;
  int co_kwonlyargcount;
  int co_nlocals;
  int co_stacksize;
  int co_flags;
  int co_firstlineno;
  PyObject *co_code;
  PyObject *co_consts;
  PyObject *co_names;
  PyObject *co_varnames;
  PyObject *co_freevars;
  PyObject *co_cellvars;
  Py_ssize_t *co_cell2arg;
  PyBytesObject *co_filename;
  PyBytesObject *co_name;
  PyObject *co_lnotab;
  void *co_zombieframe;
  PyObject *co_weakreflist;
  void *co_extra;
  unsigned char *co_opcache_map;
  void *co_opcache;
  int co_opcache_flag;
  unsigned char co_opcache_size;
} PyCodeObject;

typedef struct _frame {
  PyVarObject ob_base;
  struct _frame *f_back;
  PyCodeObject *f_code;
  PyObject *f_builtins;
  PyObject *f_globals;
  PyObject *f_locals;
  PyObject **f_valuestack;
  PyObject **f_stacktop;
  PyObject *f_trace;
  char f_trace_lines;
  char f_trace_opcodes;
  PyObject *f_gen;
  int f_lasti;
  int f_lineno;
  int f_iblock;
  char f_executing;
  PyTryBlock f_blockstack[20];
  PyObject *f_localsplus[1];
} PyFrameObject;
