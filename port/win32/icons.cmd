@echo off
cd /D %1
attrib -r *.gif >NUL 2>&1
del *.gif >NUL 2>&1
sh icons.shar
attrib -r *.gif >NUL 2>&1
