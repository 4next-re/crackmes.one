@echo off

SET appname=keygenme_solution_msvc

CALL "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -startdir=none -arch=x64 -host_arch=x64

cl /EHsc .\%appname%.cpp

DIR %appname%.*

PAUSE