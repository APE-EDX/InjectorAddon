#include <node.h>


using v8::FunctionCallbackInfo;
using v8::Isolate;
using v8::Local;
using v8::Object;
using v8::Boolean;
using v8::String;
using v8::Value;
using v8::Exception;


#ifdef _WIN32
    #include "injector_win.cc"
#else
    #include "injector_linux.cc"
#endif

void init(Local<Object> exports) {
    NODE_SET_METHOD(exports, "injectDLL", injectDLL);
    NODE_SET_METHOD(exports, "injectDLLByPID", injectDLLByPID);
}

NODE_MODULE(injector, init)
