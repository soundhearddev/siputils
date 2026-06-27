# **siputils**
### **utils for SIP**

Linux only


## Install:
test use:
``` bash
zig build -Doptimize=ReleaseSafe
```
<br>

global install:
``` bash
sudo zig build install --prefix /usr/local
```


## Usage:

### server:
The Server is config driven so a config must be parsed (default: /etc/sip/sipd.conf)

start the server:

``` bash
sudo sipd
```






create new address:
``` bash
 sipctl new <name> 
```
<br>
send message:

```
 sipctl send <identity> <host> [--port PORT] <message>
```