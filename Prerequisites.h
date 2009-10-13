#ifndef __Prerequisites_H__
#define __Prerequisites_H__

#define PLATFORM_WIN32 1
#define PLATFORM_LINUX 2

#define COMPILER_MSVC 1
#define COMPILER_GNUC 2

//find current platform 
#if defined( __WIN32__ ) || defined( _WIN32 )
#   define PLATFORM PLATFORM_WIN32
#else
#   define PLATFORM PLATFORM_LINUX
#endif

//find current compiler
#if defined( _MSC_VER )
#   define COMPILER COMPILER_MSVC
#elif defined( __GNUC__ )
#   define COMPILER COMPILER_GNUC
#endif

#if PLATFORM == PLATFORM_WIN32
#	define INLINE __inline
#	define STRDUP _strdup
#	define _Export __declspec( dllexport )

	#include <winsock.h>
#else
#	define INLINE inline
#	define STRDUP strdup
#	define _Export

	#include <sys/socket.h>
	#include <sys/select.h>
	#include <netinet/tcp.h>
	#include <netdb.h>
	#include <arpa/inet.h>
	#include <unistd.h>
	#include <pthread.h>
#endif

#if COMPILER == COMPILER_MSVC
#   pragma warning (disable : 4996)
#   pragma warning (disable : 4244)
#endif

#ifndef BYTE_ORDER
#define BIG_ENDIAN 1
#define BYTE_ORDER BIG_ENDIAN
#endif

typedef unsigned int uint;
typedef unsigned char uchr;

#endif
