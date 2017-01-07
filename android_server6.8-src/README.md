# android_server6.8

This project was intent to build ida's android_server on x86, when I reconstruct and make a successful build with source code, I found libthread_db.so cann't work on x86
(dlopen(libthread_db.so): Cannot load library: reloc_library[1311]:  1195 cannot locate 'ps_pglobal_lookup'...)
even gikdbg only has armeabi architecture, i guess it the compatibility on x86 is not so good, we have to recompile a libthread_db!!!
