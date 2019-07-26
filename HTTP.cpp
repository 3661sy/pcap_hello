const char *HTTP_METHOD_HTTP = "HTTP";
const char *HTTP_METHOD_GET = "GET";
const char *HTTP_METHOD_POST = "POST";
const char *HTTP_METHOD_PUT = "PUT";
const char *HTTP_METHOD_DELETE = "DELETE";
const char *HTTP_METHOD_CONNECT = "CONNECT";
const char *HTTP_METHOD_OPTIONS = "OPTIONS";
const char *HTTP_METHOD_TRACE = "TRACE";
const char *HTTP_METHOD_PATCH = "PATCH";

void *HTTP_METHOD[] =
{
    (void *)HTTP_METHOD_HTTP,
    (void *)HTTP_METHOD_GET,
    (void *)HTTP_METHOD_POST,
    (void *)HTTP_METHOD_PUT,
    (void *)HTTP_METHOD_DELETE,
    (void *)HTTP_METHOD_CONNECT,
    (void *)HTTP_METHOD_OPTIONS,
    (void *)HTTP_METHOD_TRACE,
    (void *)HTTP_METHOD_PATCH
    };
