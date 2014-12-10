#include <Python.h>
#include <datetime.h>
#define crypto_MODULE
#include "asn1.h"

static PyObject * crypto_ASN1Obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  crypto_ASN1Obj *self;

  if ( type == NULL ) {
    type = &crypto_ASN1Obj_Type;
  }
  self = (crypto_ASN1Obj *)type->tp_alloc(type, 0);
  if (self == NULL) {
    return (PyObject*) self;
  }
  self->tag = 0;
  self->class = 0;
  self->compound = 0;
  self->data = NULL;
  self->children = NULL;
  self->num_children = 0;
  return (PyObject *)self;
}

static int crypto_ASN1Obj_init(crypto_ASN1Obj *self, PyObject *args, PyObject *kwds)
{
  PyObject *obj=NULL;
  static char *kwlist[] = {"content"};

  if (! PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &obj))
    return -1;

  if( !obj ) return 0;

  //TODO: Init based on obj

  return 0;
}

static int crypto_ASN1Obj_traverse(crypto_ASN1Obj *self, visitproc visit, void *arg)
{
  for( int i = 0; i < self->num_children; i++ ) {
    Py_VISIT( self->children[i] );
  }
  return 0;
}


static int crypto_ASN1Obj_clear(crypto_ASN1Obj *self)
{
  for( int i = 0; i < self->num_children; i++ ) {
    Py_CLEAR(self->children[i]);
  }
  if( self->num_children > 0 ) {
    self->num_children = 0;
    free(self->children);
  }
  //TODO: Clear data if required
  return 0;
}

static void crypto_ASN1Obj_dealloc(crypto_ASN1Obj* self)
{
  crypto_ASN1Obj_clear(self);
  self->ob_type->tp_free((PyObject*)self);
}


/* METHODS */
#define DOC_HEADER(name) static char crypto_ASN1Obj_##name##_doc[] =
#define FUNC_HEADER(name) static PyObject* crypto_ASN1Obj_##name ( crypto_ASN1Obj *self, PyObject *args )

DOC_HEADER(get_tag) "\n\
    Get the tag \n\
    Arguments: self - The ASN1 object \n\
    Returns: The tag number. 0 if not set \n";
FUNC_HEADER(get_tag) {
  if ( !PyArg_ParseTuple(args, ":get_tag") )
    return NULL;
  return Py_BuildValue("i",self->tag);
}

DOC_HEADER(get_class) "\n\
    Get the class \n\
    Arguments: self - The ASN1 object \n\
    Returns: The class number. 0 if not set \n";
FUNC_HEADER(get_class) {
  if ( !PyArg_ParseTuple(args, ":get_class") )
    return NULL;
  return Py_BuildValue("i",self->class);
}

DOC_HEADER(is_compound) "\n\
    Checks if is compound object \n\
    Arguments: self - The ASN1 object \n\
    Returns: true if the object is compound \n";
FUNC_HEADER(is_compound) {
  if ( !PyArg_ParseTuple(args, ":is_compound") )
    return NULL;
  return Py_BuildValue("i",self->class);
}

DOC_HEADER(get_value) "\n\
    Gets the value of the object based on the type \n\
    Arguments: Self - The ASN1 object \n\
    Returns: different value based on the type. None will be returned for types that don't have value \n";
FUNC_HEADER(get_value) {
  if ( !PyArg_ParseTuple(args, ":get_value") )
    return NULL;
  Py_XINCREF(self->data);
  return self->data;
}


/* END METHODS */


#define ADD_METHOD(name) { #name, (PyCFunction)crypto_ASN1Obj_##name, METH_VARARGS, crypto_ASN1Obj_##name##_doc }
static PyMethodDef crypto_ASN1Obj_methods[] =
{
  ADD_METHOD(get_tag),
  ADD_METHOD(get_class),
  ADD_METHOD(is_compound),
  ADD_METHOD(get_value),
  {NULL,NULL}
};

static PyTypeObject crypto_ASN1Obj_Type = {
  PyObject_HEAD_INIT(NULL)
    0,
  "ASN1Obj",
  sizeof( crypto_ASN1Obj ),
  0,                         /*tp_itemsize*/
  (destructor)crypto_ASN1Obj_dealloc,                         /*tp_dealloc*/
  0,                         /*tp_print*/
  0,                         /*tp_getattr*/
  0,                         /*tp_setattr*/
  0,                         /*tp_compare*/
  0,                         /*tp_repr*/
  0,                         /*tp_as_number*/
  0,                         /*tp_as_sequence*/
  0,                         /*tp_as_mapping*/
  0,                         /*tp_hash */
  0,                         /*tp_call*/
  0,                         /*tp_str*/
  0,                         /*tp_getattro*/
  0,                         /*tp_setattro*/
  0,                         /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,        /*tp_flags*/
  "ASN1Obj objects",           /* tp_doc */
  (traverseproc)crypto_ASN1Obj_traverse,                   /* tp_traverse */
  (inquiry)crypto_ASN1Obj_clear,                   /* tp_clear */
  0,                   /* tp_richcompare */
  0,                   /* tp_weaklistoffset */
  0,                   /* tp_iter */
  0,                   /* tp_iternext */
  crypto_ASN1Obj_methods,             /* tp_methods */
  0,             /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc)crypto_ASN1Obj_init,      /* tp_init */
  0,                         /* tp_alloc */
  crypto_ASN1Obj_new,                 /* tp_new */
};

int init_crypto_ASN1Obj( PyObject * dict )
{
  if (PyType_Ready(&crypto_ASN1Obj_Type) < 0)
    return -1;
  //crypto_ASN1Obj_Type.ob_type = &PyType_Type;
  //Py_INCREF( &crypto_ASN1Obj_Type );
  PyDict_SetItemString( dict, "ASN1Obj", ( PyObject * ) & crypto_ASN1Obj_Type );
  return 1;
}

/* SERIALIZATION */

static PyObject* stringToDatetime(char*buf, long len) {
  PyObject *datetime;
  struct tm time_tm;
  char zone;

  if ( ( len != 13 ) && ( len != 15 ) ) {
      Py_RETURN_NONE;
  }

  if ( len == 13 ) {
    len = sscanf( (const char*)buf, "%02d%02d%02d%02d%02d%02d%c", &( time_tm.tm_year ), &( time_tm.tm_mon ), 
                       &( time_tm.tm_mday ), &( time_tm.tm_hour ), &( time_tm.tm_min ), &( time_tm.tm_sec ), &zone );
    //HACK: We don't expect this code to run past 2100s or receive certs pre-2000
    time_tm.tm_year += 2000;
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) ) {
      Py_RETURN_NONE;
    }
  }

  if ( len == 15 ) {
    len = sscanf( (const char*)buf, "20%02d%02d%02d%02d%02d%02d%c", &( time_tm.tm_year ), &( time_tm.tm_mon ), &( time_tm.tm_mday ),
                       &( time_tm.tm_hour ), &( time_tm.tm_min ), &( time_tm.tm_sec ), &zone );
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) ) {
      Py_RETURN_NONE;
    }
  }
#ifdef _BSD_SOURCE
  time_tm.tm_zone = &zone;
#endif
  printf("DATE IS %d-%d-%d %d:%d:%d\n", time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
                                         time_tm.tm_min, time_tm.tm_sec );

  datetime = PyDateTime_FromDateAndTime( time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
                                         time_tm.tm_min, time_tm.tm_sec, 0 );

  printf("DATE IS %d-%d-%d %d:%d:%d\n", time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
                                         time_tm.tm_min, time_tm.tm_sec );
  /* dont understand */
  if ( !datetime ) {
    Py_RETURN_NONE;
  }
  return datetime;

}

static crypto_ASN1Obj* loads_asn1(char* buf, long len, long *len_done, int nindent ){
  crypto_ASN1Obj *obj;
  long xlen, header_len;
  char *ctmp, *xbuf = buf;
  int xtag, xclass, ret;
  long tmp;
  ASN1_OBJECT *o=NULL;
  ASN1_OCTET_STRING *os=NULL;
  ASN1_INTEGER *ai;
  ASN1_BIT_STRING *bs;
  char indent[(nindent*4)+1];
  for(int i = 0; i< (nindent*4)+1 ; i++ ){
    indent[i] = ' ';
  }
  indent[(nindent*4)] = 0;

  ret=ASN1_get_object((const unsigned char**)&xbuf,&xlen,&xtag,&xclass,len);
  if (ret & 0x80){
    //TODO: err
    return NULL;
  }
  header_len = xbuf - buf;
  *len_done = header_len;
  if( (obj=(crypto_ASN1Obj*)crypto_ASN1Obj_new(NULL,NULL,NULL) ) == NULL ) {
    return NULL;
  }
  obj->compound = ret & V_ASN1_CONSTRUCTED;
  obj->tag = xtag;
  obj->class = xclass;
  if( obj->compound ) {
    char *child_buf = xbuf;
    long child_len;
    crypto_ASN1Obj* child;
    int alloc_space = 1;
    obj->children = (crypto_ASN1Obj**)malloc( sizeof( crypto_ASN1Obj** ) * alloc_space );
    while( child_buf < xbuf + xlen ) {
      child = loads_asn1(child_buf,len-(*len_done), &child_len, nindent + 1 );
      if ( child == NULL ) {
        Py_XDECREF( obj );
        return NULL;
      }
      (*len_done) += child_len;
      child_buf += child_len;
      if ( child->tag == V_ASN1_EOC && child->class == 0 ) {
        Py_XDECREF( child );
        break;
      }
      if( obj->num_children >= alloc_space ) {
        alloc_space *= 2;
        obj->children = (crypto_ASN1Obj**)realloc( obj->children, sizeof( crypto_ASN1Obj** ) * alloc_space );
      }
      obj->children[obj->num_children] = child;
      obj->num_children++;
    }
    if(obj->num_children>alloc_space) {
      obj->children = (crypto_ASN1Obj**)realloc( obj->children, sizeof( crypto_ASN1Obj** ) * obj->num_children );
    }
    obj->data = PyTuple_New(obj->num_children);
    for(int i = 0; i< obj->num_children; i++ ) {
      printf( "INC %d %p\n", i, obj->children[i]->data );
      Py_XINCREF(obj->children[i]->data);
      PyTuple_SetItem( obj->data, i, obj->children[i]->data );
    }
    return obj;
  }
  *len_done += xlen;
  printf( "%d %s %s %ld\n", nindent, indent, ASN1_tag2str( obj->tag ), xlen );
  switch ( obj->tag ) {
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_NUMERICSTRING:
      obj->data = PyString_FromStringAndSize( xbuf, xlen );
      break;
    case V_ASN1_UTF8STRING:
      obj->data = PyUnicode_FromStringAndSize( xbuf, xlen );
      break;
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
      obj->data = stringToDatetime( xbuf, xlen );
      break;
    case V_ASN1_BOOLEAN:
      //HACK: Maybe need another ref of buf? It is pointer of local var :P
      tmp = (long)d2i_ASN1_BOOLEAN(NULL,(const unsigned char**)&buf,xlen+header_len); 
      if ( tmp < 0 ) { /*TODO: Errr*/ return NULL; }
      if ( tmp ) {
        obj->data =Py_True; 
      } else {
        obj->data = Py_False; 
      };
      Py_INCREF( obj->data );
      break;
    case V_ASN1_OBJECT:
      if (d2i_ASN1_OBJECT(&o,(const unsigned char**)&buf,xlen+header_len) == NULL) { /*TODO: REPORT ERR */ return NULL; }
      ctmp = (char*)malloc(256);
      i2t_ASN1_OBJECT(ctmp,256,o);
      ASN1_OBJECT_free(o);
      obj->data = PyString_FromString( ctmp );
      free(ctmp);
      break;
    case V_ASN1_OCTET_STRING:
      os=d2i_ASN1_OCTET_STRING(NULL,(const unsigned char**)&buf,xlen+header_len); 
      if( os!= NULL && os->length>0) {
        obj->data = PyByteArray_FromStringAndSize((const char*)os->data,os->length);
        M_ASN1_OCTET_STRING_free(os);
        os=NULL;
      }
      break;
    case V_ASN1_INTEGER:
    case V_ASN1_NEG_INTEGER:
      ai = d2i_ASN1_INTEGER(NULL,(const unsigned char**)&buf,xlen+header_len);
      tmp = ASN1_INTEGER_get(ai);
      M_ASN1_INTEGER_free(ai);
      obj->data = PyLong_FromLong(tmp);
      break;
    case V_ASN1_ENUMERATED:
      ai = d2i_ASN1_ENUMERATED(NULL,(const unsigned char**)&buf,xlen+header_len);
      tmp = ASN1_ENUMERATED_get(ai);
      M_ASN1_ENUMERATED_free(ai);
      obj->data = PyLong_FromLong(tmp);
      //TODO: delete with:M_ASN1_ENUMERATED_free(bs); 
      //As int with: (long)ASN1_ENUMERATED_get(obj->data)
      break;
    case V_ASN1_NULL:
      obj->data = Py_None;
      Py_INCREF(obj->data);
      break;
    case V_ASN1_BIT_STRING:
      bs = d2i_ASN1_BIT_STRING(NULL,(const unsigned char**)&buf,xlen+header_len);
      if( bs!= NULL && bs->length>0) {
        obj->data = PyByteArray_FromStringAndSize((const char*)bs->data, bs->length);
        M_ASN1_OCTET_STRING_free(bs);
        bs=NULL;
      } else {
        obj->data = Py_None;
        Py_INCREF( obj->data );
      }
      break;
    default:
      //DON?T KNOW WAHT TO DO
      Py_XDECREF(obj);
      printf( "KK %d %s\n", obj->tag, ASN1_tag2str(obj->tag));
      return NULL;
  }
  return obj;
}

PyObject* crypto_ASN1_loads(PyObject* spam, PyObject* args) {
  char* buf;
  long len, done;
  if (!PyArg_ParseTuple( args, "s#|:asn1_loads", &buf, &len )){
    return NULL;
  }
  return (PyObject*)loads_asn1(buf, len, &done, 0 );
}

PyObject* crypto_ASN1_dumps(PyObject* spam, PyObject* args) {
  return NULL;
}
