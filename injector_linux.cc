#include <hotpatch_config.h>
#include <hotpatch.h>

bool injectToPID(const char* path, int32_t pid)
{
    hotpatch_t* hp = hotpatch_create(pid, false);
    if (!hp)
    {
        return false;
    }

    uintptr_t dlres = 0;
    uintptr_t symres = 0;
    int rc = hotpatch_inject_library(hp, path, "loadMsg", NULL, 0, &dlres, &symres);
    hotpatch_destroy(hp);

    return rc >=0;
}

void injectDLL(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    args.GetReturnValue().Set(Boolean::New(isolate, false));
}

void injectDLLByPID(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // Check the number of arguments passed.
    if (args.Length() < 3)
    {
        // Throw an Error that is passed back to JavaScript
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    }

    // Check the argument types
    if (!args[0]->IsInt32() || !args[1]->IsString() || !args[2]->IsString())
    {
        isolate->ThrowException(Exception::TypeError(
            String::NewFromUtf8(isolate, "Wrong arguments")));
        return;
    }

    int32_t pid = args[0]->Int32Value();

	v8::String::Utf8Value pathV8(args[1]->ToString());
	char* path = *pathV8;

    bool success = injectToPID(path, pid);
    args.GetReturnValue().Set(Boolean::New(isolate, success));
}
