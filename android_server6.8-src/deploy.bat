adb remount
adb forward tcp:1234 tcp:1234
adb push C:\Users\Administrator\workspace\androidserver\obj\local\x86\android_server /system/bin/
adb shell chmod 777 /system/bin/android_server
adb shell  ./system/bin/android_server 
pause