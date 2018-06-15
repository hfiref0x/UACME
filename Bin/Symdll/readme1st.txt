Put in this directory

dbghelp.dll
symsrv.dll

both from Debugging Tools for Windows (NOT from Windows itself).

Ref:
https://msdn.microsoft.com/en-us/library/windows/hardware/ff551063(v=vs.85).aspx
http://www.microsoft.com/whdc/DevTools/WDK/WDKpkg.mspx

Without those dlls application will not output additional info.

Application expects Symdll directory in the process current directory. So before running it, copy Symdll folder to the same folder where application located

e.g. if UacView64.exe located in C:\test, then move to it Symdll directory, so it will be subdirectory of C:\test -> C:\test\Symdll.
