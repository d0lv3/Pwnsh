# PWNSH - Reverse Shell Payload Generator

<p align="center">
  <img src="https://img.shields.io/badge/bash-5.0+-green.svg" alt="Bash Version">
  <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos-lightgrey.svg" alt="Platform">
</p>

A comprehensive, interactive reverse shell payload generator with an intuitive UI and mouse support. Perfect for penetration testing, CTFs, and security research.

![PWNSH Demo](demo.gif)

## Features

- 🖱️ **Mouse & Keyboard Navigation** - Click or use arrow keys to navigate
- 🎨 **Beautiful UI** - Color-coded, easy-to-read interface
- 📋 **100+ Payloads** - Covering all major languages and techniques
- 🎯 **Listener Commands** - Every payload includes the corresponding listener
- 🔧 **Categories** - Organized by language/tool for quick access
- ⚡ **Zero Dependencies*** - Works out of the box (*figlet optional)

##  Installation

```bash
# Clone the repository
git clone https://github.com/d0lv3/pwnsh.git

# Navigate to directory
cd pwnsh

# Make executable
chmod +x pwnsh.sh

# Run
./pwnsh.sh <LHOST> <LPORT>
```

##  Usage

### Basic Usage
```bash
./pwnsh.sh 10.10.14.5 4444
```

### Interactive Mode
```bash
./pwnsh.sh
# You'll be prompted to enter LHOST and LPORT
```

### Navigation
- **Arrow Keys**: Navigate up/down through menu
- **Mouse**: Click on any menu item
- **Enter**: Select highlighted option
- **Interactive Menus**: All payload screens pause for review

##  Payload Categories

### 1. **Bash Payloads**
- TCP redirections
- UDP shells
- File descriptor manipulation
- Various bash techniques

### 2. **Netcat Payloads**
- Traditional nc with -e
- mkfifo methods
- BusyBox variants
- OpenBSD netcat
- ncat alternatives

### 3. **Python Payloads**
- Python 2 & 3 variants
- PTY spawning shells
- IPv4 & IPv6 support
- Minimal one-liners

### 4. **PHP Payloads**
- exec, shell_exec, system
- passthru, popen, proc_open
- Backtick execution
- Multiple technique variants

### 5. **PowerShell Payloads**
- Standard reverse shells
- Base64 encoded versions
- ConPtyShell integration
- Windows-optimized payloads

### 6. **Perl/Ruby Payloads**
- Socket-based connections
- No /bin/sh variants
- Fork-based shells
- Cross-platform options

### 7. **Web Shells**
- Minimal PHP shells
- Interactive web shells
- URL-encoded payloads
- Web-to-reverse shell techniques

### 8. **Java/Groovy Payloads**
- Runtime.exec() methods
- Socket connections
- Process builders

### 9. **Other Languages**
- Node.js
- Golang
- Lua
- AWK
- Dart
- Crystal

### 10. **Network Tools**
- Socat (TCP & TTY)
- Telnet
- OpenSSL encrypted shells
- SQLite3 tricks
- Zsh modules

### 11. **C/C# Payloads**
- C# TCP clients
- Compiled binaries
- Windows-specific shells

### 12. **Bind Shells**
- Python bind shells
- PHP bind shells
- Netcat bind shells
- Perl bind shells

### 13. **MSFVenom Payloads**
- Windows Meterpreter
- Linux ELF binaries
- PHP backdoors
- WAR files
- Android APKs

##  Example Workflow

1. Start your listener:
```bash
nc -lvnp 4444
```

2. Run PWNSH:
```bash
./pwnsh.sh 10.10.14.5 4444
```

3. Navigate to your desired payload category (e.g., Bash Payloads)

4. Copy the payload and execute on target system

5. Catch the shell on your listener!

## 🔧 Requirements

- Bash 4.0 or higher
- Standard Linux/Unix utilities (cat, echo, read)
- **Optional**: `figlet` for ASCII art banner
- **Optional**: `base64`, `iconv` for PowerShell base64 encoding

### Installing Optional Dependencies

**Debian/Ubuntu:**
```bash
sudo apt install figlet
```

**Arch Linux:**
```bash
sudo pacman -S figlet
```

**macOS:**
```bash
brew install figlet
```

##  Screenshots

### Main Menu
```
         ____  _       ___   _  _____ __  __
        / __ \| |     / / | / |/ ___// / / /
       / /_/ / | /| / /  |/ /\__ \/ /_/ / 
      / ____/| |/ |/ / /|  /___/ / __  /  
     /_/     |__/|__/_/ |_//____/_/ /_/   

========================================================
  Reverse Shell Payload Generator
  Made by: 0xd0lv3
  Instagram: @d0lv3 | LinkedIn: www.linkedin.com/in/d0lv3/
========================================================

Target: 10.10.14.5:4444

============ PAYLOAD CATEGORIES ============

Use arrow keys or mouse to navigate. Press Enter to select.

  Bash Payloads
  Netcat Payloads
  Python Payloads
  ...
```

##  Security Notice

This tool is intended for:
- ✅ Authorized penetration testing
- ✅ Security research
- ✅ Educational purposes
- ✅ CTF competitions
- ✅ Red team operations with proper authorization

**Do NOT use this tool on systems you don't own or have explicit permission to test.**

##  Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-payload`)
3. Commit your changes (`git commit -am 'Add new payload'`)
4. Push to the branch (`git push origin feature/new-payload`)
5. Open a Pull Request

### Adding New Payloads

To add a new payload, edit the appropriate function and use the `show_payload` format:

```bash
show_payload "Payload Name" \
    "payload command here with ${LHOST} and ${LPORT}" \
    "listener command here with ${LPORT}"
```

##  TODO

- [ ] Add clipboard copy functionality (xclip/pbcopy integration)
- [ ] Export all payloads to text file
- [ ] Search/filter functionality
- [ ] Obfuscated payload variants
- [ ] TTY upgrade commands section
- [ ] Payload customization (e.g., change shell from /bin/bash to /bin/sh)
- [ ] History of recently used payloads
- [ ] Favorites/bookmarking system

##  Known Issues

- Mouse support may not work in all terminal emulators
- PowerShell base64 encoding requires `iconv` (fallback message shown if unavailable)
- Some terminals may not support all ANSI escape sequences

##  License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

##  Author

**0xd0lv3**

- Instagram: [@d0lv3](https://instagram.com/d0lv3)
- LinkedIn: [d0lv3](https://www.linkedin.com/in/d0lv3/)
- GitHub: [@d0lv3](https://github.com/d0lv3)

##  Acknowledgments

- Inspired by various reverse shell cheat sheets
- PayloadsAllTheThings
- PentestMonkey Reverse Shell Cheat Sheet
- GTFOBins
- HackTricks

##  Disclaimer

This tool is provided for educational and ethical testing purposes only. The author assumes no liability and is not responsible for any misuse or damage caused by this program. Use responsibly and only on systems you have permission to test.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/d0lv3">0xd0lv3</a>
</p>

<p align="center">
  ⭐ Star this repository if you found it helpful!
</p>
