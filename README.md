
# Nightowl

Nightowl is a tool designed to lock onto overlooked internal network paths, uncover hidden active subnets, and quickly determine which targets are still alive.


![alt text](./pic/LOGO.png)


This project has passed functional tests in the network environments of large enterprises and educational institutions. It can perform tracking and detection without requiring authentication operations via a network authentication server.

# Build


For Linux:
```
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/n1ght0wl-linux-amd64 ./n1ght0wl.go
```

For Windows:
```
$ CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/n1ght0wl-windows-amd64.exe ./n1ght0wl.go
```

![alt text](./pic/image.png)


# Install

For Ubuntu / Debian-based systems:
```bash
sudo apt update
sudo apt install traceroute -y
```

For CentOS / RHEL / Fedora systems:
```bash
sudo yum install traceroute -y
# Or for Fedora
sudo dnf install traceroute -y
```

For Arch Linux:
```bash
sudo pacman -S traceroute
```

 
 


# Usage

PS: Running this tool requires administrator privileges!!!

`$ sudo ./n1ght0wl`

![alt text](./pic/image-1.png)

Use the `Up` and `Down` arrow keys to select a network interface, then choose the traced routing table.

![alt text](./pic/image-2.png)


![alt text](./pic/image-3.png)


`$ cat C-192/20251210.nps`

You can use the probed network segments for further enumeration with nmap or other tools...

`$ nmap -sn -iL C-192/20251210.nps`


![alt text](./pic/image-4.png)