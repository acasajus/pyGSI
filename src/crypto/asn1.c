#include <Python.h>
#include <datetime.h>
#include "asn1.h"
#include "crypto.h"

static PyObject * crypto_ASN1_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  crypto_ASN1 *self;

  if ( type == NULL ) {
    type = &crypto_ASN1_Type;
  }
  self = (crypto_ASN1 *)type->tp_alloc(type, 0);
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

static int init_crypto_ASN1_from_pyobject(crypto_ASN1* self, PyObject *obj){
  self->data = obj;
  Py_INCREF( obj );
  if( PyString_Check( obj ) ) {
    self->tag = V_ASN1_IA5STRING;
  } else if ( PyByteArray_Check( obj ) ) {
    self->tag = V_ASN1_OCTET_STRING;
  } else if ( PyUnicode_Check( obj ) ) {
    self->tag = V_ASN1_UTF8STRING;
  } else if ( PyBool_Check( obj ) ) {
    self->tag = V_ASN1_BOOLEAN;
  } else if ( PyDateTime_Check( obj ) ) {
    self->tag = V_ASN1_UTCTIME;
  } else if ( PyLong_Check( obj ) ) {
    self->tag = V_ASN1_INTEGER;
  } else if ( PyInt_Check( obj ) ) {
    self->tag = V_ASN1_INTEGER;
  } else if ( Py_None == obj ) {
    self->tag = V_ASN1_NULL;
  } else if ( PyTuple_Check( obj ) ) {
    self->tag = V_ASN1_SET;
    self->compound = 1;
    self->num_children = PyTuple_Size(obj);
    self->children = (crypto_ASN1**)malloc(sizeof(crypto_ASN1*)*(self->num_children));
    for( long i = 0; i < self->num_children; i ++ ) {
      crypto_ASN1* c = (crypto_ASN1*)crypto_ASN1_new(NULL,NULL,NULL);
      init_crypto_ASN1_from_pyobject(c,PyTuple_GetItem(obj,i));
      self->children[i] = c;
    }
  } else if ( PyList_Check( obj ) ) {
    self->tag = V_ASN1_SEQUENCE;
    self->compound = 1;
    self->num_children = PyList_Size(obj);
    self->children = (crypto_ASN1**)malloc(sizeof(crypto_ASN1*)*(self->num_children));
    for( long i = 0; i < self->num_children; i ++ ) {
      crypto_ASN1* c = (crypto_ASN1*)crypto_ASN1_new(NULL,NULL,NULL);
      init_crypto_ASN1_from_pyobject(c,PyList_GetItem(obj,i));
      self->children[i] = c;
    }
  } else return 1;

  return 0;
}

static int crypto_ASN1_init(crypto_ASN1 *self, PyObject *args, PyObject *kwds)
{
  PyObject *obj=NULL;

  if (! PyArg_ParseTuple(args, "O", &obj))
    return -1;

  if( !obj ) return -1;

  return init_crypto_ASN1_from_pyobject(self,obj);
}

static int crypto_ASN1_traverse(crypto_ASN1 *self, visitproc visit, void *arg)
{
  for( int i = 0; i < self->num_children; i++ ) {
    Py_VISIT( self->children[i] );
  }
  return 0;
}


static int crypto_ASN1_clear(crypto_ASN1 *self)
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

static void crypto_ASN1_dealloc(crypto_ASN1* self)
{
  crypto_ASN1_clear(self);
  self->ob_type->tp_free((PyObject*)self);
}


/* METHODS */
#define DOC_HEADER(name) static char crypto_ASN1_##name##_doc[] =
#define FUNC_HEADER(name) static PyObject* crypto_ASN1_##name ( crypto_ASN1 *self, PyObject *args )

DOC_HEADER(get_tag) "\n\
    Get the tag \n\
    Arguments: self - The ASN1 object \n\
    Returns: The tag number. 0 if not set \n";
FUNC_HEADER(get_tag) {
  if ( !PyArg_ParseTuple(args, ":get_tag") )
    return NULL;
  return Py_BuildValue("i",self->tag);
}

DOC_HEADER(get_tag_str) "\n\
    Get the tag \n\
    Arguments: self - The ASN1 object \n\
    Returns: The tag name as a string. empty if not set \n";
FUNC_HEADER(get_tag_str) {
  if ( !PyArg_ParseTuple(args, ":get_tag_str") )
    return NULL;
  return PyString_FromString( ASN1_tag2str( self->tag ) );
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
  return Py_BuildValue("i",self->compound);
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

DOC_HEADER(convert_to_object) "\n\
    Converts a string into an asn1 object \n\
    Arguments: Self - The ASN1 object \n\
    Returns: None \n";
FUNC_HEADER(convert_to_object) {
  if ( !PyArg_ParseTuple(args, ":convert_to_object") )
    return NULL;
  if( !PyString_Check( self->data ) ) {
    PyErr_SetString( PyExc_TypeError, "Only strins can be converted to objects" );
    return NULL;
  }
  self->tag = V_ASN1_OBJECT;
  Py_RETURN_NONE;
}


DOC_HEADER(dump) "\n\
    Dump object to ASN1 DER encoded form\n\
    Arguments: Self - The ASN1 object \n\
    Returns: bytearray with the ASN1 DER dump \n";
FUNC_HEADER(dump) {
  BUF_MEM *bptr;
  BIO *mem;
  PyObject *ret;

  if ( !PyArg_ParseTuple(args, ":dump") )
    return NULL;

  mem = BIO_new(BIO_s_mem());
  crypto_ASN1_inner_dump(self,mem);
  BIO_get_mem_ptr(mem, &bptr);
  ret = PyString_FromStringAndSize(bptr->data,bptr->length);
  BIO_free(mem);

  return ret;
}

/* END METHODS */

static Py_ssize_t ASN1_len(crypto_ASN1* self) {   
  return self->num_children;
}

static PyObject* ASN1_getitem(crypto_ASN1* self, Py_ssize_t pos ) {
  if( pos >= self->num_children ) {
    PyErr_SetString( PyExc_IndexError, "Index out of bounds" );
    return NULL;
  }
  Py_INCREF( self->children[pos] );
  return (PyObject*) self->children[pos];
}

static int ASN1_setitem(crypto_ASN1* self, Py_ssize_t pos, PyObject* obj ){
  if( pos >= self->num_children ) {
    PyErr_SetString( PyExc_IndexError, "Index out of bounds" );
    return -1;
  }
  if( ! PyObject_TypeCheck( obj, &crypto_ASN1_Type ) ) {
    PyErr_SetString( PyExc_TypeError, "Expected ASN1 type" );
    return -1;
  }
  Py_INCREF( obj );
  Py_XDECREF( self->children[pos] );
  self->children[pos] = (crypto_ASN1*)obj;
  return 0;
}
/* END SEQUENCE METHODS */

static PySequenceMethods crypto_ASN1_sequence_methods = {
      (lenfunc)ASN1_len,  /* sq_length */
      NULL, /* sq_concat */
      NULL, /* sq_repeat */
      (ssizeargfunc)ASN1_getitem, /* sq_item */
      NULL, /* sq_slice */
      (ssizeobjargproc)ASN1_setitem, /* sq_ass_item */
      NULL, /* sq_ass_slice */
      NULL, /* sq_contains */
      NULL, /* sq_inplace_concat */
      NULL, /* sq_inplace_repeat */
};

#define ADD_METHOD(name) { #name, (PyCFunction)crypto_ASN1_##name, METH_VARARGS, crypto_ASN1_##name##_doc }
static PyMethodDef crypto_ASN1_methods[] =
{
  ADD_METHOD(get_tag),
  ADD_METHOD(get_tag_str),
  ADD_METHOD(get_class),
  ADD_METHOD(is_compound),
  ADD_METHOD(get_value),
  ADD_METHOD(convert_to_object),
  ADD_METHOD(dump),
  {NULL,NULL}
};


static PyTypeObject crypto_ASN1_Type = {
  PyObject_HEAD_INIT(NULL)
    0,
  "ASN1",
  sizeof( crypto_ASN1 ),
  0,                         /*tp_itemsize*/
  (destructor)crypto_ASN1_dealloc,                         /*tp_dealloc*/
  0,                         /*tp_print*/
  0,                         /*tp_getattr*/
  0,                         /*tp_setattr*/
  0,                         /*tp_compare*/
  0,                         /*tp_repr*/
  0,                         /*tp_as_number*/
  &crypto_ASN1_sequence_methods,  /*tp_as_sequence*/
  0,                         /*tp_as_mapping*/
  0,                         /*tp_hash */
  0,                         /*tp_call*/
  0,                         /*tp_str*/
  0,                         /*tp_getattro*/
  0,                         /*tp_setattro*/
  0,                         /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,        /*tp_flags*/
  "ASN1 objects",           /* tp_doc */
  (traverseproc)crypto_ASN1_traverse,                   /* tp_traverse */
  (inquiry)crypto_ASN1_clear,                   /* tp_clear */
  0,                   /* tp_richcompare */
  0,                   /* tp_weaklistoffset */
  0,                   /* tp_iter */
  0,                   /* tp_iternext */
  crypto_ASN1_methods,             /* tp_methods */
  0,             /* tp_members */
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc)crypto_ASN1_init,      /* tp_init */
  0,                         /* tp_alloc */
  crypto_ASN1_new,                 /* tp_new */
};

int init_crypto_ASN1( PyObject * dict )
{
  if (PyType_Ready(&crypto_ASN1_Type) < 0)
    return -1;
  //crypto_ASN1_Type.ob_type = &PyType_Type;
  //Py_INCREF( &crypto_ASN1_Type );
  PyDict_SetItemString( dict, "ASN1", ( PyObject * ) & crypto_ASN1_Type );

  PyDateTime_IMPORT;
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
    len = sscanf( (const char*)buf, "%04d%02d%02d%02d%02d%02d%c", &( time_tm.tm_year ), &( time_tm.tm_mon ), &( time_tm.tm_mday ),
        &( time_tm.tm_hour ), &( time_tm.tm_min ), &( time_tm.tm_sec ), &zone );
    /* dont understand */
    if ( ( len != 7 ) || ( zone != 'Z' ) ) {
      Py_RETURN_NONE;
    }
  }
#ifdef _BSD_SOURCE
  time_tm.tm_zone = &zone;
#endif
  datetime = PyDateTime_FromDateAndTime( time_tm.tm_year, time_tm.tm_mon, time_tm.tm_mday, time_tm.tm_hour, 
      time_tm.tm_min, time_tm.tm_sec, 0 );

  /* dont understand */
  if ( !datetime ) {
    Py_RETURN_NONE;
  }
  return datetime;

}


crypto_ASN1* loads_asn1(char* buf, long len, long *len_done ){
  crypto_ASN1 *obj;
  long xlen, header_len;
  char *ctmp, *xbuf = buf;
  int xtag, xclass, ret;
  long tmp;
  ASN1_OBJECT *o=NULL;
  ASN1_OCTET_STRING *os=NULL;
  ASN1_INTEGER *ai;
  ASN1_BIT_STRING *bs;
  
  ret=ASN1_get_object((const unsigned char**)&xbuf,&xlen,&xtag,&xclass,len);
  if (ret & 0x80){
    exception_from_error_queue();
    return NULL;
  }
  header_len = xbuf - buf;
  *len_done = header_len;
  if( (obj=(crypto_ASN1*)crypto_ASN1_new(NULL,NULL,NULL) ) == NULL ) {
    exception_from_error_queue();
    return NULL;
  }
  obj->compound = ret & V_ASN1_CONSTRUCTED;
  obj->tag = xtag;
  obj->class = xclass;
  if( obj->compound ) {
    char *child_buf = xbuf;
    long child_len;
    crypto_ASN1* child;
    int alloc_space = 1;
    obj->children = (crypto_ASN1**)malloc( sizeof( crypto_ASN1** ) * alloc_space );
    while( child_buf < xbuf + xlen ) {
      child = loads_asn1(child_buf,len-(*len_done), &child_len );
      if ( child == NULL ) {
        Py_XDECREF( obj );
        exception_from_error_queue();
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
        obj->children = (crypto_ASN1**)realloc( obj->children, sizeof( crypto_ASN1** ) * alloc_space );
      }
      obj->children[obj->num_children] = child;
      obj->num_children++;
    }
    if(obj->num_children>alloc_space) {
      obj->children = (crypto_ASN1**)realloc( obj->children, sizeof( crypto_ASN1** ) * obj->num_children );
    }
    obj->data = PyTuple_New(obj->num_children);
    for(int i = 0; i< obj->num_children; i++ ) {
      Py_XINCREF(obj->children[i]->data);
      PyTuple_SetItem( obj->data, i, obj->children[i]->data );
    }
    return obj;
  }
  *len_done += xlen;
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
      obj->data = PyByteArray_FromStringAndSize((const char*)xbuf,xlen);
  }
  return obj;
}

PyObject* crypto_ASN1_loads(PyObject* spam, PyObject* args) {
  char* buf;
  long len, done;
  if (!PyArg_ParseTuple( args, "s#|:asn1_loads", &buf, &len )){
    return NULL;
  }
  return (PyObject*)loads_asn1(buf, len, &done );
}


int crypto_ASN1_inner_dump(crypto_ASN1* self, BIO* bdata) {
  unsigned char source[256];
  unsigned char *buf=source,*dyn=NULL;
  long tmp;
  PyObject *pytmp;
  ASN1_OBJECT *aob=NULL;
  ASN1_OCTET_STRING *aos=NULL;
  ASN1_INTEGER *ain;
  ASN1_NULL anull;
  struct tm time_tm;

  if( buf == NULL ) { return 0; }
  if( self->compound ) {
    BIO *sbio = BIO_new(BIO_s_mem());
    BUF_MEM *bm;
    for( long i = 0; i < self->num_children; i ++ ) {
      if( 0 == crypto_ASN1_inner_dump( self->children[i], sbio ) ) {
        BIO_free(sbio);
        return 0;
      }
    }
    BIO_get_mem_ptr(sbio,&bm);
    ASN1_put_object( &buf, 1, bm->length, self->tag, self->class );
    BIO_write( bdata, source, buf - source );
    BIO_write( bdata, bm->data, bm->length );
    BIO_free(sbio);
    return 1;
  }
  switch ( self->tag ) {
    case V_ASN1_PRINTABLESTRING:
    case V_ASN1_T61STRING:
    case V_ASN1_IA5STRING:
    case V_ASN1_VISIBLESTRING:
    case V_ASN1_NUMERICSTRING:
      ASN1_put_object( &buf, 0, PyString_Size( self->data ), self->tag, self->class );
      BIO_write( bdata, source, buf - source );
      BIO_write( bdata, PyString_AsString( self->data ), PyString_Size( self->data ) );
      break;
    case V_ASN1_UTF8STRING:
      pytmp = PyUnicode_AsUTF8String( self->data );
      if( pytmp == NULL ) return 0;

      ASN1_put_object( &buf, 0, PyString_Size( pytmp ), self->tag, self->class );
      BIO_write( bdata, source, buf - source );
      BIO_write( bdata, PyString_AsString( pytmp ), PyString_Size( self->data ) );
      Py_DECREF( pytmp );
      break;
    case V_ASN1_UTCTIME:
    case V_ASN1_GENERALIZEDTIME:
      time_tm.tm_year = PyDateTime_GET_YEAR( self->data );
      time_tm.tm_mon = PyDateTime_GET_MONTH( self->data );
      time_tm.tm_mday = PyDateTime_GET_DAY( self->data );
      time_tm.tm_hour = PyDateTime_DATE_GET_HOUR( self->data );
      time_tm.tm_min = PyDateTime_DATE_GET_MINUTE( self->data );
      time_tm.tm_sec = PyDateTime_DATE_GET_SECOND( self->data );
      ASN1_put_object( &buf, 0, 15, self->tag, self->class );
      sprintf( (char*)buf, "20%02d%02d%02d%02d%02d%02dZ", time_tm.tm_year , time_tm.tm_mon, 
          time_tm.tm_mday , time_tm.tm_hour , time_tm.tm_min , time_tm.tm_sec );
      BIO_write( bdata, source, ( buf - source ) + 15 );
      break;
    case V_ASN1_BOOLEAN:
      i2d_ASN1_BOOLEAN( PyBool_Check( self->data ), &buf );
      BIO_write( bdata, source, buf - source );
      break;
    case V_ASN1_OBJECT:
			if( ( aob = OBJ_txt2obj( PyString_AsString( self->data ), 0 ) ) == NULL ) {
				PyErr_SetString( PyExc_ValueError, "Unknown object id" );
				return 0;
			}
			if( i2d_ASN1_OBJECT( aob, &buf ) == 0 ) {
        exception_from_error_queue();
        return 0;
			}
      BIO_write( bdata, source, buf - source );
      break;
    case V_ASN1_OCTET_STRING:
    case V_ASN1_BIT_STRING:
      aos = ASN1_OCTET_STRING_new();
      aos->data = (unsigned char*) PyByteArray_AsString( self->data );
      aos->length = PyByteArray_Size( self->data );
      dyn = (unsigned char*) malloc(aos->length + 256 );
      buf = dyn;
      switch (self->tag) {
        case V_ASN1_OCTET_STRING:
          tmp = i2d_ASN1_OCTET_STRING( aos, &dyn ) ;
          break;
        case V_ASN1_BIT_STRING:
          tmp = i2d_ASN1_BIT_STRING( aos, &dyn ) ;
          break;
      }
      if( 0 == tmp ) {
        free( buf );
        exception_from_error_queue();
        return 0;
      }
      BIO_write( bdata, buf, dyn - buf);
      free( buf );
      break;
    case V_ASN1_NULL:
      i2d_ASN1_NULL( &anull, &buf );
      BIO_write( bdata, source, buf - source );
      break;
    case V_ASN1_INTEGER:
    case V_ASN1_NEG_INTEGER:
      ain = ASN1_INTEGER_new();
      ASN1_INTEGER_set( ain, PyLong_AsLong( self->data ) );
      if( 0 == i2d_ASN1_INTEGER( ain, &buf ) ) {
        ASN1_INTEGER_free(ain);
        exception_from_error_queue();
        return 0;
      }
      ASN1_INTEGER_free(ain);
      BIO_write( bdata, source, buf - source );
      break;
    case V_ASN1_ENUMERATED:
      ain = ASN1_ENUMERATED_new();
      ASN1_ENUMERATED_set( ain, PyLong_AsLong( self->data ) );
      if( 0 == i2d_ASN1_ENUMERATED( ain, &buf ) ) {
        ASN1_ENUMERATED_free(ain);
        exception_from_error_queue();
        return 0;
      }
      ASN1_ENUMERATED_free(ain);
      BIO_write( bdata, source, buf - source );
      break;
  }
  return 1;
}
