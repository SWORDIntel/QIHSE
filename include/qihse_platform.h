#ifndef QIHSE_PLATFORM_H
#define QIHSE_PLATFORM_H

/**
 * @file qihse_platform.h
 * @brief Platform Abstraction Layer (PAL) for QIHSE
 * 
 * Provides cross-platform macros, types, and abstraction wrappers to enable 
 * QIHSE to compile natively as a Windows DLL (_WIN32) or a Linux Shared Object.
 * 
 * Maps POSIX/Linux-specific subsystems (pthreads, mmap, dlopen, io_uring, sockets)
 * to their Windows equivalents (WinThreads, VirtualAlloc, LoadLibrary, IOCP, Winsock2).
 */

#ifdef _WIN32
    // --- WINDOWS DLL COMPILE FLAGS ---
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <io.h>
    
    // Dynamic Library Exports
    #define QIHSE_API __declspec(dllexport)
    
    // Memory Abstractions (mmap -> VirtualAlloc)
    #define PROT_READ     PAGE_READONLY
    #define PROT_WRITE    PAGE_READWRITE
    #define MAP_PRIVATE   0
    #define MAP_ANONYMOUS MEM_COMMIT | MEM_RESERVE
    #define MAP_FAILED    NULL

    static inline void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
        (void)addr; (void)fd; (void)offset; (void)flags;
        DWORD win_prot = PAGE_READWRITE;
        if (prot == PROT_READ) win_prot = PAGE_READONLY;
        return VirtualAlloc(NULL, length, MEM_COMMIT | MEM_RESERVE, win_prot);
    }
    
    static inline int munmap(void* addr, size_t length) {
        (void)length;
        return VirtualFree(addr, 0, MEM_RELEASE) ? 0 : -1;
    }

    // Dynamic Loading Abstractions (dlopen -> LoadLibrary)
    #define RTLD_NOW 0
    #define RTLD_GLOBAL 0
    static inline void* dlopen(const char* filename, int flags) {
        (void)flags;
        return (void*)LoadLibraryA(filename);
    }
    static inline void* dlsym(void* handle, const char* symbol) {
        return (void*)GetProcAddress((HMODULE)handle, symbol);
    }
    static inline int dlclose(void* handle) {
        return FreeLibrary((HMODULE)handle) ? 0 : -1;
    }

    // Threading Abstractions (pthread -> Windows Threads)
    // NOTE: For full compatibility, we recommend compiling with pthreads-win32.
    // However, if compiling strictly native MSVC, these stubs will map the core routines.
    #ifndef __MINGW32__
typedef HANDLE pthread_t;
    typedef CRITICAL_SECTION pthread_mutex_t;
    
    static inline int pthread_mutex_init(pthread_mutex_t *m, void *attr) {
        (void)attr;
        InitializeCriticalSection(m);
        return 0;
    }
    static inline int pthread_mutex_lock(pthread_mutex_t *m) {
        EnterCriticalSection(m);
        return 0;
    }
    static inline int pthread_mutex_unlock(pthread_mutex_t *m) {
        LeaveCriticalSection(m);
        return 0;
    }
    static inline int pthread_mutex_destroy(pthread_mutex_t *m) {
        DeleteCriticalSection(m);
        return 0;
    }
#endif

    // File I/O mappings
    #define open _open
    #define close _close
    #define read _read
    #define write _write

    // Sockets / Networking
    #define close_socket closesocket
    
    // We cannot map io_uring directly on Windows.
    // The implementation files (qihse_file_posix.c) must check #ifdef _WIN32 
    // and use IOCP (I/O Completion Ports) instead of io_uring.
    #define QIHSE_USE_IOCP 1

#else
    // --- LINUX / POSIX NATIVE COMPILE FLAGS ---
    #include <pthread.h>
    #include <sys/mman.h>
    #include <dlfcn.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    
    // Dynamic Library Exports
    #define QIHSE_API __attribute__((visibility("default")))
    
    // Sockets
    #define close_socket close
    
    // Asynchronous I/O
    #define QIHSE_USE_IO_URING 1

#endif

#endif // QIHSE_PLATFORM_H
