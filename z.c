/* z.c (platform stuff) -- esl */

#if defined(__GNUC__) && defined(__linux)
  #ifdef _FEATURES_H
    #warning too late to select features
  #endif
  #if !defined( _GNU_SOURCE )
    #define _GNU_SOURCE
  #endif
  #define _ISOC99_SOURCE
  #define _XOPEN_SOURCE 500
  #if defined( __INTERIX )
    #define _XOPEN_SOURCE_EXTENDED 1
  #endif
#endif
  
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <wchar.h>
#include <assert.h>

#if defined(_MSC_VER)
#ifdef _POSIX_
#undef _POSIX_
#endif
#if (_WIN32_WINNT < 0x0500)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif
#include <fcntl.h>
#include <io.h>
#include <share.h> /* for _SH_DENYNO */
#include <direct.h>
#include <sys/types.h>
#include <process.h> /* for getpid */
#include <locale.h> /* for setlocale */
#include <sys/stat.h> /* for _S_IREAD|_S_IWRITE */
#include <windows.h>
#if _MSC_VER >= 1600
#include <crtversion.h>
#endif
#if defined(_VC_CRT_MAJOR_VERSION) && (_VC_CRT_MAJOR_VERSION >= 14)
void __cdecl __acrt_errno_map_os_error(unsigned long const oserrno);
#define _dosmaperr(oserrno) __acrt_errno_map_os_error(oserrno)
#else
_CRTIMP void __cdecl _dosmaperr(unsigned long);
#endif
#define getcwd _getcwd
#define chdir _chdir
#define mkdir(d,m) _mkdir(d)
#define rmdir _rmdir
#define stat(a,b) _stat(a,b)
#define isatty _isatty
#define fileno _fileno
#define setbmode(fp) _setmode(_fileno(fp),_O_BINARY)
typedef struct _stat stat_t;
#define S_ISDIR(m) (((m) & _S_IFMT) == _S_IFDIR)
#define S_ISREG(m) (((m) & _S_IFMT) == _S_IFREG)
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#ifndef EEXIST 
#include <errno.h>
#endif
#elif defined(__GNUC__) && defined(__APPLE__) 
#include <mach-o/dyld.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#define setbmode(fp) /* nothing */
typedef struct stat stat_t; 
#elif defined(__GNUC__) && defined(__linux)
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define setbmode(fp) /* nothing */
#ifdef _LFS64_LARGEFILE
#define stat(a,b) stat64(a,b)
typedef struct stat64 stat_t; 
#else
typedef struct stat stat_t; 
#endif
#elif defined(__GNUC__) && (defined(_WIN32) || defined(__INTERIX))
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define setbmode(fp) /* nothing */
#ifdef _LFS64_LARGEFILE
#define stat(a,b) stat64(a,b)
typedef struct stat64 stat_t; 
#else
typedef struct stat stat_t; 
#endif
#if defined(__INTERIX)
#include <signal.h>
#include <strings.h>
#endif
#elif defined(__SVR4) && defined(__sun)
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#define setbmode(fp) /* nothing */
#ifdef _LFS64_LARGEFILE
#define stat(a,b) stat64(a,b)
typedef struct stat64 stat_t; 
#else
typedef struct stat stat_t; 
#endif
#include <libgen.h>
#include <signal.h>
#else
#error "b.c: add your platform here" 
#endif

#include "b.h"
#include "z.h"

/* path name components */

#ifdef _WIN32 /* works as _WIN64 too */
int dirsep = '\\';
#else
int dirsep = '/';
#endif

/* dirpath is "", "/" or ends in separator ".../" */

/* ends in "foo/" */
bool hasdpar(const char* path)
{
  char* pc; size_t len, dnlen;
  assert(path);
  len = strlen(path);
  if (!len) return false; /* "" has no parents */
  pc = (char*)path + len;
  /* expect, but not enforce trailing sep */
  if (pc[-1] == '/') --pc;
#ifdef _WIN32 /* works as _WIN64 too */
  else if (pc[-1] == '\\') --pc;
#endif
  /* trailing sep skipped, look for previous one */
  dnlen = 0;
  while (pc > path) {
    if (pc[-1] == '/') break;
#ifdef _WIN32 /* works as _WIN64 too */
    else if (pc[-1] == '\\') break;
    else if (pc[-1] == ':') break;
#endif
    --pc; ++dnlen;
  }
  /* succeed if saw non-empty last segment */
  return dnlen > 0;
}

/* all up to last "foo/" */
size_t spandpar(const char* path)
{
  char* pc; size_t len;
  assert(path);
  len = strlen(path);
  if (!len) return len; /* "" has no parents */
  pc = (char*)path + len;
  /* expect, but not enforce trailing sep */
  if (pc[-1] == '/') --pc;
#ifdef _WIN32 /* works as _WIN64 too */
  else if (pc[-1] == '\\') --pc;
#endif
  /* trailing sep skipped, look for previous one */
  while (pc > path) {
    if (pc[-1] == '/') break;
#ifdef _WIN32 /* works as _WIN64 too */
    else if (pc[-1] == '\\') break;
    else if (pc[-1] == ':') break;
#endif
    --pc;
  }
  /* succeed no matter what we chopped off */
  return pc - path;
}
 
/* last "foo/" */
char* getdname(const char* path)
{
  /* must be the same as path + spandpar(path) */
  char* pc; size_t len;
  assert(path);
  len = strlen(path);
  pc = (char*)path + len;
  if (!len) return pc; /* "" has no parents */
  /* expect, but not enforce trailing sep */
  if (pc[-1] == '/') --pc;
#ifdef _WIN32 /* works as _WIN64 too */
  else if (pc[-1] == '\\') --pc;
#endif
  /* trailing sep skipped, look for previous one */
  while (pc > path) {
    if (pc[-1] == '/') break;
#ifdef _WIN32 /* works as _WIN64 too */
    else if (pc[-1] == '\\') break;
    else if (pc[-1] == ':') break;
#endif
    --pc;
  }
  /* succeed no matter what we chopped off */
  return pc;
}

/* spans dir ("", "/", or "..../foo/") */
size_t spanfdir(const char* path)
{
  char* pc;
  assert(path);
  if ((pc = strrchr(path, '/')) != NULL)
    return pc+1-path;
#ifdef _WIN32 /* works as _WIN64 too */
  else if ((pc = strrchr(path, '\\')) != NULL)
    return pc+1-path;
  else if ((pc = strrchr(path, ':')) != NULL)
    return pc+1-path;
#endif
  return 0;
}

/* returns trailing file name */
char *getfname(const char *path)
{
  char *s1, *s2, *s3, *s = (char*)path;
  s1 = strrchr(path, '\\'), s2 = strrchr(path, '/'), s3 = strrchr(path, ':');
  if (s1 && s < s1+1) s = s1+1; 
  if (s2 && s < s2+1) s = s2+1; 
  if (s3 && s < s3+1) s = s3+1;
  return s;
}

/* returns file base (up to, but not including last .) */
size_t spanfbase(const char* path)
{
  char* fn; char* pc;
  assert(path);
  fn = getfname(path); 
  if ((pc = strrchr(path, '.')) != NULL && pc >= fn)
    return pc-path;
  return strlen(path);
}

/* returns trailing file extension ("" or ".foo") */
char* getfext(const char* path)
{
  char* fn; char* pc;
  assert(path);
  fn = getfname(path); 
  if ((pc = strrchr(path, '.')) != NULL && pc >= fn)
    return (char*)pc;
  return (char*)(path+strlen(path));
}

/* parse path as <root> <relpath> */
bool pathparse2(const char *path, size_t *proot, size_t *prelpath)
{
  bool ok = true;
  size_t root = 0, rest = 0; 
  /* no path is the same as empty one */
  if (!path) path = ""; else rest = strlen(path);
  /* chop off the root if any */
#ifdef _WIN32 /* works as _WIN64 too */
  /* by default, there's no root */
  if ((path[0] == '\\' || path[0] == '/') && (path[1] == '\\' || path[1] == '/')) {
    const char *pc, *pc2;
    if (((pc = strchr(path+2, '\\')) || (pc = strchr(path+2, '/'))) && 
        ((pc2 = strchr(pc+1, '\\')) || (pc2 = strchr(pc+1, '/')))) {
       /* \\<server>\<share>\ root found */
       size_t rsz = (size_t)(pc2+1 - path);
       root = rsz;
       rest -= rsz;
       /* check for root bogosity, including legal \\?\ which we can't handle */
       if (strcspn(path+root, ":*?\"<>|") < rsz) ok = false;
    }
  } else if (isalpha(path[0]) && path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
    /* <drive_letter>:\ root found */
    root = 3;
    rest -= 3;
  }
  /* check for relpath bogosity, including legal cases like C:foo which we can't handle */
  if (path[root] == '\\' || path[root] == '/') ok = false;
  else if (strcspn(path+root, ":*?\"<>|") != rest) ok = false;
#else /* Un**x */
  if (path[0] == '/') {
    root = 1;
    rest -= 1;
  }
  /* check for relpath bogosity, including legal cases like ~/foo which we can't handle */
  if (strcspn(path+root, "~") != rest) ok = false;
#endif
  if (proot) *proot = root;
  if (prelpath) *prelpath = rest;
  return ok;
}

/* trim optional separator at the end of pname */
extern char *trimdirsep(char *pname)
{
  size_t len = strlen(pname);
  if (!len) return pname;
  if (pname[len-1] == '/') pname[len-1] = 0;
#ifdef WIN32
  if (pname[len-1] == '\\') pname[len-1] = 0;
#endif
  return pname;
}

void cbputdirsep(cbuf_t *pcb)
{
  assert(pcb);
#ifdef _WIN32 /* works as _WIN64 too */
  cbputc('\\', pcb);
#else /* Un**x */
  cbputc('/', pcb);
#endif
}

/* quote arg as single argument for command line */
void cbputarg(const char *arg, cbuf_t *pcb)
{
#ifdef _WIN32 /* works as _WIN64 too */
  /* quote for cmd utils and crt */
  char *treif = "&|()<>^%\t \"";
  if (!arg) return;
  assert(pcb);
  if (strlen(arg) > strcspn(arg, treif)) {
    /* string is nonempty and contains junk */
    if (!strchr(arg, '\"') && !strchr(arg, '%')) {
      /* simple case: just be careful with trailing \s */
      const char *pe = arg + strlen(arg);
      while (pe > arg && pe[-1] == '\\') --pe;
      /* output all up to trailing \s, quoted */
      cbputc('\"', pcb);
      cbput(arg, pe-arg, pcb);
      cbputc('\"', pcb);
      /* now trailing \s */
      if (*pe) cbputs(pe, pcb);
    } else {
      /* fasten your seatbelts: this is not an average escaping code! */
      int c;
      cbputc('\"', pcb);
      while ((c = *arg++)) {
        switch (c) {
          /* " is doubled so that CMD does not go crazy over odd number of "s */
          case '\"': cbputc('\"', pcb); cbputc('\"', pcb); break;
          case '%': { /* make sure no env vars is substituted! */
            if (*arg && !strchr("&|()<>^%\t \"\\", *arg)) {
              /* may look like a variable, ok outside quotes */
              cbputc(c, pcb);
              cbputc('\"', pcb); /* switch to regular mode */
              cbputc(*arg++, pcb);
              cbputc('\"', pcb); /* switch back to "quoted" mode */
            } else {
              /* won't look like a variable to cmd.exe */
              cbputc(c, pcb);
            }
          } break;
          case '\\': { /* now this is getting interesting! */
            int bscnt = 1; /* count all adjacent /s, starting with this one */
            while (*arg == '\\') ++arg, ++bscnt;
            if (*arg == 0 || *arg == '\"') /* potential \" situation! */
              bscnt *= 2; /* need twice as much \s here! */
            while (bscnt-- > 0) cbputc('\\', pcb);
            /* now backslash magic is defused, normal processing continues */
          } break;
          /* all other chars are written as-is */
          default: cbputc(c, pcb); break;  
        }
      }
      cbputc('\"', pcb);
    }
  } else {
    if (*arg) cbputs(arg, pcb);
    else cbputs("\"\"", pcb);
  }
#else /* *nix */
  /* quote for /bin/sh & the like */
  char *kosher = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz@/-+_.%,";
  if (!arg) return;
  assert(pcb);
  if (strlen(arg) > strspn(arg, kosher)) {
    cbputc('\'', pcb);
    while (*arg) {
      int c = *arg++;
      if (c == '\'') cbputs("\'\\\'\'", pcb);
      else cbputc(c, pcb);
    }
    cbputc('\'', pcb);
  } else {
    if (*arg) cbputs(arg, pcb);
    else cbputs("''", pcb);
  }
#endif  
}


#if defined(_MSC_VER)
static char *fixapath(const char *apath, cbuf_t *pcb)
{
  /* _wstat & friends don't like dir paths ending in slash */
  size_t len = strlen(apath);
  if (len > 1 && apath[len-2] != ':' && (apath[len-1] == '\\' || apath[len-1] == '/')) {
    return cbset(pcb, apath, len-1);
  }
  /* also, they don't like drive current dir's */
  if (len == 2 && isalpha(apath[0]) && apath[1] == ':') {
    cbsets(pcb, apath);
    cbputc('.', pcb); /* X:. is ok */
    return cbdata(pcb);
  }
  /* looks kosher */
  return (char*)apath;
}
#endif

/* simplified version of stat */
bool fsstat(const char *path, fsstat_t *ps)
{
#if defined(_MSC_VER)
  int res = -1;
  struct _stati64 s;
  DWORD r = 0xffffffff;
  cbuf_t cb = mkcb();
  assert(ps);
  path = fixapath(path, &cb);
  res = _stati64(path, &s);
  if (res < 0 && path[0] == '\\' && path[1] == '\\') r = GetFileAttributesA(path);
  cbfini(&cb);
  if (res < 0 && r != 0xffffffff && (r & FILE_ATTRIBUTE_DIRECTORY)) {
    /* //server/share - pretend it's a directory */
    ps->isreg = false;
    ps->isdir = true;
    ps->atime = ps->ctime = ps->mtime = (time_t)-1;
    ps->size = 0;
    return true;
  }
  if (res < 0) return false;
#else
  /* Un*x? assume utf-8 is native to OS */
  stat_t s;
  assert(path); assert(ps);
  if (stat(path, &s) < 0) return false;
#endif
  ps->atime = s.st_atime;
  ps->ctime = s.st_ctime;
  ps->mtime = s.st_mtime;
  ps->isreg = S_ISREG(s.st_mode);
  ps->isdir = S_ISDIR(s.st_mode);
  ps->size = (uint64_t)s.st_size;
  return true; 
}

/* check that path points to existing file */
bool fexists(const char *path)
{
  fsstat_t s;
  assert(path);
  if (!fsstat(path, &s)) return false;
  return s.isreg; 
}

/* check that path points to existing dir */
bool direxists(const char *path)
{
  fsstat_t s;
  assert(path);
  if (!fsstat(path, &s)) return false;
  return s.isdir; 
}

/* Windows dirent */
#if defined(_MSC_VER)

/* Windows implementation of the directory stream type (taken from SCM).
 * The miscellaneous Unix `readdir' implementations read directory data
 * into a buffer and return `struct dirent *' pointers into it. */

#include <sys/types.h>

typedef struct dirstream {
  void* fd;           /* File descriptor.  */
  char *data;         /* Directory block.  */
  size_t allocation;  /* Space allocated for the block.  */
  size_t size;        /* Total valid data in the block.  */
  size_t offset;      /* Current offset into the block.  */
  off_t filepos;      /* Position of next entry to read.  */
  wchar_t *mask;      /* Initial file mask. */
} DIR;

struct dirent {
  off_t d_off;
  size_t d_reclen;
  char d_name[FILENAME_MAX];
};

DIR *opendir (const char *name);
struct dirent *readdir(DIR *dir);
int closedir (DIR *dir);
void rewinddir (DIR *dir);
void seekdir (DIR *dir, off_t offset);
off_t telldir (DIR *dir);

DIR *opendir(const char *name)
{
  DIR *dir;
  HANDLE hnd;
  char *file;
  WIN32_FIND_DATAW find;
  buf_t pwcv; /* to store wide chars */
  wchar_t *wfile, *ws;
  
  if (!name || !*name) return NULL;

  pwcv = mkbuf(sizeof(wchar_t));
  file = emalloc(strlen(name) + 3);
  strcpy(file, name);
  if (file[strlen(name) - 1] != '/' && file[strlen(name) - 1] != '\\')
    strcat(file, "/*");
  else
    strcat(file, "*");
  
  { /* convert from ANSI code page multibyte */
    bufresize(&pwcv, FILENAME_MAX);
    wfile = bufdata(&pwcv);
    if (mbstowcs(wfile, file, FILENAME_MAX) == (size_t) -1)
      wfile = NULL;
  }
  
  if (wfile == NULL ||
      (hnd = FindFirstFileW(wfile, &find)) == INVALID_HANDLE_VALUE) {
    free(file);
    buffini(&pwcv);
    return NULL;
  }
  
  ws = ecalloc(wcslen(wfile)+1, sizeof(wchar_t));
  wcscpy(ws, wfile);

  dir = emalloc(sizeof(DIR));
  dir->mask = ws;
  dir->fd = hnd;
  dir->data = malloc(sizeof(WIN32_FIND_DATAW));
  dir->allocation = sizeof(WIN32_FIND_DATAW);
  dir->size = dir->allocation;
  dir->filepos = 0;
  memcpy(dir->data, &find, sizeof(WIN32_FIND_DATAW));
  free(file);
  buffini(&pwcv);
  return dir;
}

struct dirent *readdir(DIR *dir)
{
  static struct dirent entry; /* non-reentrant! */
  WIN32_FIND_DATAW *find;
  cbuf_t cb; /* to store utf-8 chars */
  char *fname;
  
  assert(dir);
  assert((HANDLE)(dir->fd) != INVALID_HANDLE_VALUE);
  find = (WIN32_FIND_DATAW *)(dir->data);

  if (dir->filepos) {
    if (!FindNextFileW((HANDLE)(dir->fd), find))
      return NULL;
  }

  cb = mkcb();
  entry.d_off = dir->filepos;
  { /* convert to ANSI code page multibyte */
    fname = cballoc(&cb, sizeof(entry.d_name));
    if (wcstombs(fname, find->cFileName, sizeof(entry.d_name)) == (size_t)-1)
      fname = NULL;
  }
  if (fname == NULL) {
    cbfini(&cb);
    return NULL;
  }
  entry.d_reclen = strlen(fname);
  if (entry.d_reclen+1 > sizeof(entry.d_name)) {
    cbfini(&cb);
    return NULL;
  }
  strncpy(entry.d_name, fname, sizeof(entry.d_name));
  dir->filepos++;
  
  cbfini(&cb);
  return &entry;
}

int closedir(DIR *dir)
{
  HANDLE hnd = (HANDLE)(dir->fd);
  free(dir->data);
  free(dir->mask);
  free(dir);
  return FindClose(hnd) ? 0 : -1;
}

void rewinddir(DIR *dir)
{
  HANDLE hnd = (HANDLE)(dir->fd);
  WIN32_FIND_DATAW *find = (WIN32_FIND_DATAW *)(dir->data);
  FindClose(hnd);
  hnd = FindFirstFileW(dir->mask, find);
  dir->fd = hnd;
  dir->filepos = 0;
}

void seekdir(DIR *dir, off_t offset)
{
  off_t n;
  rewinddir(dir);
  for (n = 0; n < offset; n++) {
    if (FindNextFileW((HANDLE)(dir->fd), (WIN32_FIND_DATAW *)(dir->data)))
       dir->filepos++;
  }
}

off_t telldir(DIR *dir)
{
  return dir->filepos;
}

#endif /* Windows dirent */

/* list full dir content as file/dir names */
bool dir(const char *dirpath, dsbuf_t *pdsv)
{
   DIR *pdir;
   struct dirent *pde;
   assert(pdsv);
   assert(dirpath);
   dsbclear(pdsv);
   /* NB: dirent is not reentrant! */
   pdir = opendir(dirpath);
   if (!pdir) return false;
   while ((pde = readdir(pdir)) != NULL) {
     char *name = pde->d_name;
     dsbpushbk(pdsv, &name);
   }
   closedir(pdir);
   return true;
}

/* emkdir: create new last dir on the path, throw errors */
void emkdir(const char *dir)
{
  assert(dir);
  if (mkdir(dir, 0777) != 0)
    eprintf("cannot mkdir '%s':", dir);
}

/* ermdir: remove empty last dir on the path, throw errors */
void ermdir(const char *dir)
{
  assert(dir);
  if (rmdir(dir) != 0)
    eprintf("cannot rmdir '%s':", dir);
}

/* split relative path into segments */
static void rel_splitpath(const char *path, size_t plen, dsbuf_t *psegv)
{
  dsbclear(psegv);
  if (plen) {
    cbuf_t cb = mkcb(), cbs = mkcb();
#ifdef _WIN32 /* works as _WIN64 too */
    char *sep = "\\/";
#else /* Un**x */
    char *sep = "/";
#endif
    char *str = cbset(&cb, path, plen), *seg;
    while ((seg = strtoken(str, sep, &str, &cbs)) != NULL)
      dsbpushbk(psegv, &seg);
    cbfini(&cb);
    cbfini(&cbs);
  }
}

/* creates final dirs on the path as needed */
void emkdirp(const char *path)
{
  size_t rlen, plen;
  assert(path);
  if (!pathparse2(path, &rlen, &plen)) {
    eprintf("cannot mkdirs '%s':", path);
  } else {
    size_t i;
    cbuf_t cb = mkcb();
    dsbuf_t segv; dsbinit(&segv);
    rel_splitpath(path+rlen, plen, &segv);
    cbput(path, rlen, &cb);
    /* write back the resulting path */
    for (i = 0; i < dsblen(&segv); ++i) {
      dstr_t *pds = dsbref(&segv, i);
      if (i > 0) cbputdirsep(&cb);
      cbputs(*pds, &cb);
      path = cbdata(&cb);
      if (!direxists(path))
        emkdir(path);
    }
    cbfini(&cb);
    dsbfini(&segv);
  }
}

/* opens new tmp file in w+b; it is deleted when file closed or program exits/crashes */
/* mode should be "w+b" or "w+t" (makes difference on Windows) */
FILE *etmpopen(const char *mode)
{
  FILE *fp = NULL;
#if defined(_MSC_VER) 
  /* standard tmpnam is no good; use ours */
  char *fname, fnbuf[100];
  int c = 'a';
  int pid = _getpid(); 
  int fd = -1;
  bool text = false;
  assert(mode);
  if (mode && strchr(mode, 't')) text = true;
  for (;;) {
    sprintf(fnbuf, "cutmp_%c%d", c, pid); 
    fname = _tempnam(NULL, fnbuf);
    if (!fname) break;
    fd = _sopen(fname,
            _O_CREAT|_O_EXCL|_O_RDWR|
            (text ? _O_TEXT : _O_BINARY)|
            _O_TEMPORARY|_O_SHORT_LIVED,
            _SH_DENYNO,
            _S_IREAD|_S_IWRITE);
    if (fd != -1) break;
    if (errno != EEXIST) break;
    if (c >= 'z') break; 
    ++c;
  }
  /* shouldn't have problems opening good fd if got enough FILEs */
  if (fd != -1) fp = _fdopen(fd, mode ? mode : "w+b");
#else
  /* linuxes tmpfile fits the bill; let's use it */
  assert(mode); /* required but ignored: makes no difference here */
  fp = tmpfile();
#endif  
  if (!fp) eprintf("out of temp files");
  return fp;
}

/* epopen: open a pipe or throw fileerr */
FILE* epopen(const char *cmd, const char *mode)
{ 
  FILE* fp = NULL;
  assert(cmd); assert(mode);
#if defined(_MSC_VER)
  fp = _popen(cmd, mode);
#else
  /* some libraries fail on "rb"/"wb" */
  mode = strchr(mode, 'w') ? "w" : "r";
  fp = popen(cmd, mode);
#endif
  if (!fp) eprintf("pipe open error: %s", cmd);
  return fp;
}

/* epclose: close an open pipe */
int epclose(FILE *pipe)
{ 
  int res;
  assert(pipe);
#if defined(_MSC_VER)
  res = _pclose(pipe);
#else
  res = pclose(pipe);
#endif
  if (res < 0) eprintf("pipe close error");
  return res;
}


/* sets stdin/stdout into binary mode (no-op on Unix) */
void fbinary(FILE *stdfile)
{
  setbmode(stdfile);
}

/* check that file is a tty */
bool fisatty(FILE *fp)
{
  assert(fp);
  return isatty(fileno(fp)); 
}

#if defined(_MSC_VER) && (_MSC_VER >= 1400)
#define fseeki64 _fseeki64
#define ftelli64 _ftelli64
#elif !defined(__64BIT__) && (PLATFORM_POSIX_VERSION >= 200112L)
#define fseeki64 fseeko
#define ftelli64 fseeko
#elif defined(__MINGW32__) && defined(__MSVCRT__) && !defined(__STRICT_ANSI__) && !defined(__NO_MINGW_LFS)
#define fseeki64 fseeko64
#define ftelli64 fseeko64
#else
#define fseeki64 fseek
#define ftelli64 ftell
#endif

int fseekll(FILE *fp, long long off, int org)
{
  return fseeki64(fp, off, org);
}

long long ftellll(FILE *fp)
{
  return ftelli64(fp);
}

/* set utf-8 code page */
#ifdef _WIN32 /* works as _WIN64 too */
void setu8cp(void)
{
  setlocale(LC_ALL, ".UTF8");
  /* system("chcp 65001"); */
}
#else
void setu8cp(void)
{
}
#endif


#ifdef USEZLIB
#include <zlib.h>

int zdeflate(uint8_t *dst, size_t *dlen, const uint8_t *src, size_t *slen, int lvl)
{
  int zerr, err = 0;
  z_stream zs;
  zs.zalloc = Z_NULL;
  zs.zfree = Z_NULL;
  zs.opaque = Z_NULL;
  zs.avail_in = (unsigned)*slen;
  zs.next_in = (Bytef*)src;
  zs.avail_out = (unsigned)*dlen;
  zs.next_out = (Bytef*)dst;
  zerr = deflateInit2(&zs, 
    lvl, /* level, Z_DEFAULT_COMPRESSION */
    Z_DEFLATED,
    -15, /* windowBits: max. compression, no zlib header/footer */
    9, /* memLevel: default is 8 */
    Z_DEFAULT_STRATEGY); 
  if (zerr != Z_OK) return -1;
  zerr = deflate(&zs, Z_FINISH);
  if (zerr != Z_STREAM_END) err = -2;
  zerr = deflateEnd(&zs);
  if (zerr != Z_OK) err = -3;
  if (!err) {
    *slen = (size_t)zs.total_in;
    *dlen = (size_t)zs.total_out;
  } 
  return err;
}

#else
/* small deflate/inflate by @edgararout (https://github.com/fxfactorial/sdefl) */
/* licensed under either MIT license or Unlicense (in public domain) */

#define SDEFL_MAX_OFF       (1 << 15)
#define SDEFL_WIN_SIZ       SDEFL_MAX_OFF
#define SDEFL_HASH_BITS     19
#define SDEFL_HASH_SIZ      (1 << SDEFL_HASH_BITS)
#define SDEFL_LVL_MIN       0
#define SDEFL_LVL_DEF       5
#define SDEFL_LVL_MAX       8

struct sdefl { int bits, cnt; int tbl[SDEFL_HASH_SIZ]; int prv[SDEFL_WIN_SIZ]; };

#define SDEFL_WIN_MSK       (SDEFL_WIN_SIZ-1)
#define SDEFL_MIN_MATCH     4
#define SDEFL_MAX_MATCH     258
#define SDEFL_HASH_MSK      (SDEFL_HASH_SIZ-1)
#define SDEFL_NIL           (-1)

static const unsigned char sdefl_mirror[256] = {
  #define R2(n) n, n + 128, n + 64, n + 192
  #define R4(n) R2(n), R2(n + 32), R2(n + 16), R2(n + 48)
  #define R6(n) R4(n), R4(n + 8), R4(n + 4), R4(n + 12)
  R6(0), R6(2), R6(1), R6(3),
};

static int sdefl_npow2(int n)
{
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
  return (int)++n;
}

static int sdefl_ilog2(int n)
{
  #define lt(n) n,n,n,n, n,n,n,n, n,n,n,n ,n,n,n,n
  static const char tbl[256] = {-1,0,1,1,2,2,2,2,3,3,3,3,
    3,3,3,3,lt(4),lt(5),lt(5),lt(6),lt(6),lt(6),lt(6),
    lt(7),lt(7),lt(7),lt(7),lt(7),lt(7),lt(7),lt(7)
  }; int tt, t;
  if ((tt = (n >> 16)))
    return (t = (tt >> 8)) ? 24+tbl[t]: 16+tbl[tt];
  else return (t = (n >> 8)) ? 8+tbl[t]: tbl[n];
  #undef lt
}

static unsigned sdefl_uload32(const void *p)
{
  /* hopefully will be optimized to an unaligned read */
  unsigned int n = 0;
  memcpy(&n, p, sizeof(n));
  return n;
}

static unsigned sdefl_hash32(const void *p)
{
  unsigned n = sdefl_uload32(p);
  return (n*0x9E377989)>>(32-SDEFL_HASH_BITS);
}

static unsigned char* sdefl_put(unsigned char *dst, struct sdefl *s, int code, int bitcnt)
{
  s->bits |= (code << s->cnt);
  s->cnt += bitcnt;
  while (s->cnt >= 8) {
    *dst++ = (unsigned char)(s->bits & 0xFF);
    s->bits >>= 8;
    s->cnt -= 8;
  } 
  return dst;
}

static unsigned char* sdefl_match(unsigned char *dst, struct sdefl *s, int dist, int len)
{
  static const short lxmin[] = {0,11,19,35,67,131};
  static const short dxmax[] = {0,6,12,24,48,96,192,384,768,1536,3072,6144,12288,24576};
  static const short lmin[] = {11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227};
  static const short dmin[] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,
    385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};

  /* length encoding */
  int lc = len;
  int lx = sdefl_ilog2(len - 3) - 2;
  if (!(lx = (lx < 0) ? 0: lx)) lc += 254;
  else if (len >= 258) lx = 0, lc = 285;
  else lc = ((lx-1) << 2) + 265 + ((len - lxmin[lx]) >> lx);
  if (lc <= 279) dst = sdefl_put(dst, s, sdefl_mirror[(lc - 256) << 1], 7);
  else dst = sdefl_put(dst, s, sdefl_mirror[0xc0 - 280 + lc], 8);
  if (lx) dst = sdefl_put(dst, s, len - lmin[lc - 265], lx);

  /* distance encoding */
  { int dc = dist - 1;
    int dx = sdefl_ilog2(sdefl_npow2(dist) >> 2);
    if ((dx = (dx < 0) ? 0: dx)) dc = ((dx + 1) << 1) + (dist > dxmax[dx]);
    dst = sdefl_put(dst, s, sdefl_mirror[dc << 3], 5);
    if (dx) dst = sdefl_put(dst, s, dist - dmin[dc], dx);
  }
  return dst;
}

static unsigned char* sdefl_lit(unsigned char *dst, struct sdefl *s, int c)
{
  if (c <= 143) return sdefl_put(dst, s, sdefl_mirror[0x30+c], 8);
  else return sdefl_put(dst, s, 1 + 2 * sdefl_mirror[0x90 - 144 + c], 9);
}

static int sdeflate(struct sdefl *s, unsigned char *out, const unsigned char *in, int in_len, int lvl)
{
  int p = 0;
  int max_chain = (lvl < 8) ? (1<<(lvl+1)): (1<<13);
  unsigned char *q = out;

  s->bits = s->cnt = 0;
  for (p = 0; p < SDEFL_HASH_SIZ; ++p) s->tbl[p] = SDEFL_NIL;
  p = 0;
  q = sdefl_put(q, s, 0x01, 1); /* block */
  q = sdefl_put(q, s, 0x01, 2); /* static huffman */
  while (p < in_len) {
    int run, best_len = 0, dist = 0;
    int max_match = ((in_len-p) > SDEFL_MAX_MATCH) ? SDEFL_MAX_MATCH : (in_len-p);
    if (max_match > SDEFL_MIN_MATCH) {
      int limit = ((p-SDEFL_WIN_SIZ) < SDEFL_NIL) ? SDEFL_NIL : (p-SDEFL_WIN_SIZ);
      int chain_len = max_chain;
      int i = s->tbl[sdefl_hash32(&in[p])];
      while (i > limit) {
        if (in[i+best_len] == in[p+best_len] && (sdefl_uload32(&in[i]) == sdefl_uload32(&in[p]))) {
          int n = SDEFL_MIN_MATCH;
          while (n < max_match && in[i+n] == in[p+n]) n++;
          if (n > best_len) {
            best_len = n;
            dist = p - i;
            if (n == max_match) break;
          }
        }
        if (!(--chain_len)) break;
        i = s->prv[i&SDEFL_WIN_MSK];
      }
    }
    if (lvl >= 5 && best_len >= SDEFL_MIN_MATCH && best_len < max_match) {
      const int x = p + 1;
      int tar_len = best_len + 1;
      int limit = ((x-SDEFL_WIN_SIZ) < SDEFL_NIL) ? SDEFL_NIL : (x-SDEFL_WIN_SIZ);
      int chain_len = max_chain;
      int i = s->tbl[sdefl_hash32(&in[p])];
      while (i > limit) {
        if (in[i+best_len] == in[x+best_len] && (sdefl_uload32(&in[i]) == sdefl_uload32(&in[x]))) {
          int n = SDEFL_MIN_MATCH;
          while (n < tar_len && in[i+n] == in[x+n]) n++;
          if (n == tar_len) {
            best_len = 0;
            break;
          }
        }
        if (!(--chain_len)) break;
        i = s->prv[i&SDEFL_WIN_MSK];
      }
    }
    if (best_len >= SDEFL_MIN_MATCH) {
      q = sdefl_match(q, s, dist, best_len);
      run = best_len;
    } else {
      q = sdefl_lit(q, s, in[p]);
      run = 1;
    }
    while (run-- != 0) {
      unsigned h = sdefl_hash32(&in[p]);
      s->prv[p&SDEFL_WIN_MSK] = s->tbl[h];
      s->tbl[h] = p++;
    }
  }
  /* zlib partial flush */
  q = sdefl_put(q, s, 0, 7);
  q = sdefl_put(q, s, 2, 10);
  q = sdefl_put(q, s, 2, 3);
  return (int)(q - out);
}

int zdeflate(uint8_t *dst, size_t *dlen, const uint8_t *src, size_t *slen, int lvl)
{
  struct sdefl *psds = emalloc(sizeof(struct sdefl));
  /* NB: sdeflate does not check for overflow, so make sure dlen is big enough */
  int outc = sdeflate(psds, dst, src, (int)*slen, lvl > 8 ? 8 : lvl);
  int err = (outc < 0);
  if (!err) *dlen = (size_t)outc; /* slen is not changed */
  free(psds);
  return err;
}

#endif

size_t zdeflate_bound(size_t slen)
{
  size_t a = 128 + (slen * 110) / 100;
  size_t b = 128 + slen + ((slen / (31 * 1024)) + 1) * 5;
  return (a > b) ? a : b;
}

/* 
 This code is an altered version of simple zlib format decoder by
 Mark Adler (https://github.com/madler/zlib/tree/master/contrib/puff)
 Please see the original for extensive comments on the code
  
 Copyright (C) 2002-2013 Mark Adler, all rights reserved
 version 2.3, 21 Jan 2013

 This software is provided 'as-is', without any express or implied
 warranty. In no event will the author be held liable for any damages
 arising from the use of this software.

 Permission is granted to anyone to use this software for any purpose,
 including commercial applications, and to alter it and redistribute it
 freely, subject to the following restrictions:

 1. The origin of this software must not be misrepresented; you must not
  claim that you wrote the original software. If you use this software
  in a product, an acknowledgment in the product documentation would be
  appreciated but is not required.
 2. Altered source versions must be plainly marked as such, and must not be
  misrepresented as being the original software.
 3. This notice may not be removed or altered from any source distribution.

 Mark Adler  madler@alumni.caltech.edu
*/

#define Z_MAXBITS 15
#define Z_MAXLCODES 286
#define Z_MAXDCODES 30
#define Z_MAXCODES (Z_MAXLCODES+Z_MAXDCODES)
#define Z_FIXLCODES 288

typedef struct zdst {
  const uint8_t *in; 
  size_t inlen, incnt;
  uint8_t *out;
  size_t outlen, outcnt;
  int bitbuf, bitcnt;
} zdst_t;

static int z_bits(zdst_t *s, int need, int *err)
{
  long val = s->bitbuf;
  while (s->bitcnt < need) {
    if (s->incnt == s->inlen) return *err = -12, 0;
    val |= (long)(s->in[s->incnt++]) << s->bitcnt;
    s->bitcnt += 8;
  }
  s->bitbuf = (int)(val >> need);
  s->bitcnt -= need;
  return (int)(val & ((1L << need) - 1));
}

static int z_stored(zdst_t *s)
{
  unsigned len;
  s->bitbuf = 0;
  s->bitcnt = 0;
  if (s->incnt + 4 > s->inlen) return 2;
  len = s->in[s->incnt++];
  len |= s->in[s->incnt++] << 8;
  if (s->in[s->incnt++] != (~len & 0xff) || s->in[s->incnt++] != ((~len >> 8) & 0xff)) return -2;
  if (s->incnt + len > s->inlen) return 2;
  if (s->out != NULL) {
    if (s->outcnt + len > s->outlen) return 1;
    while (len--) s->out[s->outcnt++] = s->in[s->incnt++];
  } else {
    s->outcnt += len;
    s->incnt += len;
  }
  return 0;
}

typedef struct zdhuff { short *count, *symbol; } zdhuff_t;

static int z_decode(zdst_t *s, const zdhuff_t *h)
{
  int len, code, first, count, index, bitbuf, left;
  short *next;
  bitbuf = s->bitbuf;
  left = s->bitcnt;
  code = first = index = 0;
  len = 1;
  next = h->count + 1;
  while (1) {
    while (left--) {
      code |= bitbuf & 1;
      bitbuf >>= 1;
      count = *next++;
      if (code - count < first) {
        s->bitbuf = bitbuf;
        s->bitcnt = (s->bitcnt - len) & 7;
        return h->symbol[index + (code - first)];
      }
      index += count;
      first += count;
      first <<= 1;
      code <<= 1;
      len++;
    }
    left = (Z_MAXBITS+1) - len;
    if (left == 0) break;
    if (s->incnt == s->inlen) return -12;
    bitbuf = s->in[s->incnt++];
    if (left > 8) left = 8;
  }
  return -10;
}

static int z_construct(zdhuff_t *h, const short *length, int n)
{
  int symbol, len, left;
  short offs[Z_MAXBITS+1];

  for (len = 0; len <= Z_MAXBITS; len++) h->count[len] = 0;
  for (symbol = 0; symbol < n; symbol++) (h->count[length[symbol]])++;
  if (h->count[0] == n) return 0;
  left = 1;
  for (len = 1; len <= Z_MAXBITS; len++) {
    left <<= 1;
    left -= h->count[len];
    if (left < 0) return left;
  }
  offs[1] = 0;
  for (len = 1; len < Z_MAXBITS; len++) offs[len + 1] = offs[len] + h->count[len];
  for (symbol = 0; symbol < n; symbol++)
    if (length[symbol] != 0)
      h->symbol[offs[length[symbol]]++] = symbol;

  return left;
}

static int z_codes(zdst_t *s, const zdhuff_t *lencode, const zdhuff_t *distcode)
{
  int symbol, len; unsigned dist;
  static const short lens[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
    35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
  static const short lext[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
    3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
  static const short dists[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
    257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577};
  static const short dext[30] = { 
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11,
    12, 12, 13, 13};
  do {
    symbol = z_decode(s, lencode);
    if (symbol < 0) return symbol;
    if (symbol < 256) {
      if (s->out != NULL) {
        if (s->outcnt == s->outlen) return 1;
        s->out[s->outcnt] = symbol;
      }
      s->outcnt++;
    } else if (symbol > 256) {
      int err = 0;
      symbol -= 257;
      if (symbol >= 29) return -10;
      len = lens[symbol] + z_bits(s, lext[symbol], &err);
      if (err != 0) return err;
      symbol = z_decode(s, distcode);
      if (symbol < 0) return symbol;
      dist = dists[symbol] + z_bits(s, dext[symbol], &err);
      if (err != 0) return err;
      if (s->out != NULL) {
        if (s->outcnt + len > s->outlen) return 1;
        while (len--) {
          s->out[s->outcnt] = dist > s->outcnt ? 0 : s->out[s->outcnt - dist];
          s->outcnt++;
        }
      } else {
        s->outcnt += len;
      }
    }
  } while (symbol != 256);
  return 0;
}

static int z_fixed(zdst_t *s)
{
  static int virgin = 1;
  static short lencnt[Z_MAXBITS+1], lensym[Z_FIXLCODES];
  static short distcnt[Z_MAXBITS+1], distsym[Z_MAXDCODES];
  static zdhuff_t lencode, distcode;
  if (virgin) {
    int symbol;
    short lengths[Z_FIXLCODES];
    lencode.count = lencnt, lencode.symbol = lensym;
    distcode.count = distcnt, distcode.symbol = distsym;
    for (symbol = 0; symbol < 144; symbol++) lengths[symbol] = 8;
    for (; symbol < 256; symbol++) lengths[symbol] = 9;
    for (; symbol < 280; symbol++) lengths[symbol] = 7;
    for (; symbol < Z_FIXLCODES; symbol++) lengths[symbol] = 8;
    z_construct(&lencode, lengths, Z_FIXLCODES);
    for (symbol = 0; symbol < Z_MAXDCODES; symbol++) lengths[symbol] = 5;
    z_construct(&distcode, lengths, Z_MAXDCODES);
    virgin = 0;
  }
  return z_codes(s, &lencode, &distcode);
}

static int z_dynamic(zdst_t *s)
{
  int nlen, ndist, ncode, index, err;
  short lengths[Z_MAXCODES], lencnt[Z_MAXBITS+1], lensym[Z_MAXLCODES];
  short distcnt[Z_MAXBITS+1], distsym[Z_MAXDCODES];
  zdhuff_t lencode, distcode;
  static const short order[19] =
    {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};

  lencode.count = lencnt, lencode.symbol = lensym;
  distcode.count = distcnt, distcode.symbol = distsym;
  err = 0;
  nlen = z_bits(s, 5, &err) + 257;
  ndist = z_bits(s, 5, &err) + 1;
  ncode = z_bits(s, 4, &err) + 4;
  if (err != 0) return err;
  if (nlen > Z_MAXLCODES || ndist > Z_MAXDCODES) return -3;
  for (index = 0; index < ncode; index++) {
    lengths[order[index]] = z_bits(s, 3, &err);
    if (err != 0) return err;
  }
  for (; index < 19; index++) lengths[order[index]] = 0;
  err = z_construct(&lencode, lengths, 19);
  if (err != 0) return -4;

  index = 0;
  while (index < nlen + ndist) {
    int symbol, len;
    symbol = z_decode(s, &lencode);
    if (symbol < 0) return symbol;
    if (symbol < 16) {
      lengths[index++] = symbol;
    } else {
      len = 0, err = 0;
      if (symbol == 16) {
        if (index == 0) return -5;
        len = lengths[index - 1];
        symbol = 3 + z_bits(s, 2, &err);
      } else if (symbol == 17) {
        symbol = 3 + z_bits(s, 3, &err);
      } else {
        symbol = 11 + z_bits(s, 7, &err);
      }
      if (err) return err;
      if (index + symbol > nlen + ndist) return -6;
      while (symbol--) lengths[index++] = len;
    }
  }

  if (lengths[256] == 0) return -9;

  err = z_construct(&lencode, lengths, nlen);
  if (err && (err < 0 || nlen != lencode.count[0] + lencode.count[1])) return -7;
  err = z_construct(&distcode, lengths + nlen, ndist);
  if (err && (err < 0 || ndist != distcode.count[0] + distcode.count[1])) return -8;

  return z_codes(s, &lencode, &distcode);
}

int zinflate(uint8_t *dest, size_t *destlen, const uint8_t *source, size_t *sourcelen)
{
  zdst_t s;
  int last, type, err;
  s.out = dest; /* can be NULL -- only outcnt is updated */
  s.outlen = *destlen;
  s.outcnt = 0;
  s.in = source;
  s.inlen = *sourcelen;
  s.incnt = 0;
  s.bitbuf = 0;
  s.bitcnt = 0;
  do {
    err = 0;
    last = z_bits(&s, 1, &err);
    type = z_bits(&s, 2, &err);
    if (err != 0) break;
    switch (type) {
      case 0:  err = z_stored(&s);  break;
      case 1:  err = z_fixed(&s);   break;
      case 2:  err = z_dynamic(&s); break;
      default: err = -1; break;
    }
    if (err != 0) break;
  } while (!last);
  if (err <= 0) {
    *destlen = s.outcnt;
    *sourcelen = s.incnt;
  }
  return err;
}
