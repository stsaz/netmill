/** netmill: http: HTTP status codes and messages
2022, Simon Zolin
*/

enum HTTP_STATUS {
	HTTP_200_OK,
	HTTP_206_PARTIAL,

	HTTP_301_MOVED_PERMANENTLY,
	HTTP_302_FOUND,
	HTTP_304_NOT_MODIFIED,

	HTTP_400_BAD_REQUEST,
	HTTP_403_FORBIDDEN,
	HTTP_404_NOT_FOUND,
	HTTP_405_METHOD_NOT_ALLOWED,
	HTTP_413_REQUEST_ENTITY_TOO_LARGE,
	HTTP_415_UNSUPPORTED_MEDIA_TYPE,
	HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE,

	HTTP_500_INTERNAL_SERVER_ERROR,
	HTTP_501_NOT_IMPLEMENTED,
	HTTP_502_BAD_GATEWAY,
	HTTP_504_GATEWAY_TIMEOUT,

	_HTTP_STATUS_END,
};
static const ffushort http_status_code[] = {
	200,
	206,

	301,
	302,
	304,

	400,
	403,
	404,
	405,
	413,
	415,
	416,

	500,
	501,
	502,
	504,
};
static const char http_status_msg[][32] = {
	"OK",
	"Partial",

	"Moved Permanently",
	"Found",
	"Not Modified",

	"Bad Request",
	"Forbidden",
	"Not Found",
	"Method Not Allowed",
	"Request Entity Too Large",
	"Unsupported Media Type",
	"Requested Range Not Satisfiable",

	"Internal Server Error",
	"Not Implemented",
	"Bad Gateway",
	"Gateway Timeout",
};
