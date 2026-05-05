@echo off

set appname=decodeme_solution

del %appname%.obj
del %appname%.exe

C:\masm64\bin64\ml64.exe /c %appname%.asm

C:\masm64\bin64\link.exe /SUBSYSTEM:CONSOLE /MACHINE:X64 /ENTRY:entry_point /nologo /LARGEADDRESSAWARE %appname%.obj

dir %appname%.*

pause