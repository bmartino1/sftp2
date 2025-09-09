[preview]: https://raw.githubusercontent.com/MarkusMcNugen/docker-templates/master/sftp/SFTP.png "SFTP"

![alt text][preview]

# SFTP with Fail2ban
Easy to use SFTP ([SSH File Transfer Protocol](https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol)) server with [OpenSSH](https://en.wikipedia.org/wiki/OpenSSH) and [Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) installed for extra hardening against brute force attacks. A Updated Fork of MarkusMcNugen/docker-sftp Orginaly Forked from atmoz/sftp... Due to age of application, It was time for a refresh...

---

**More Info:**  
Unraid Forum: [https://forums.unraid.net/topic/189050-support-sftp-fail2ban](https://forums.unraid.net/topic/189050-support-sftp-fail2ban)

Docker Hub: [https://hub.docker.com/r/bmmbmm01/sftp](https://hub.docker.com/r/bmmbmm01/sftp)

# Docker Features
* Base: [phusion/baseimage](https://hub.docker.com/r/phusion/baseimage/)
* --Ubuntu Noble Docker image
* Size: ~310MB
* Hardened default ssh config
* Fail2ban
* Optional config volume can be mounted for custom ssh and fail2ban configuration and easily viewing fail2ban log

# Optional Update script

Docker Varaible -e Auto_Update=
true 	Runs /stage/updateapps.sh if present
custom	Runs /config/updateapps.sh if present
false or empty skips updates

```
cd /config
wget https://raw.githubusercontent.com/bmartino1/docker-sftp/refs/heads/master/updateapps.sh
```

you can add the updateapps.sh script in the /conf and this should install the lattes repo from archive.ubuntu.com to install the latest openssh and fail2ban application.
(Bleeding edge) Otherwise see notes as that is what's packaged for stable release following release cycles of [phusion/baseimage](https://hub.docker.com/r/phusion/baseimage/)

# Run container from Docker registry
```
docker run \
    --cap-add=NET_ADMIN --cap-add=NET_RAW
    -v /host/config/path:/config \
    -p 22:22 -d bmmbmm01/sftp:latest \
    user:pass:::upload
```
User "user" with password "pass" can login with sftp and upload files to a folder called "upload". No mounted directories or custom UID/GID. Later you can inspect the files and use `--volumes-from` to mount them somewhere else.

# Volumes, Paths, and Ports
## Volumes
| Volume | Required | Function | Example |
|----------|----------|----------|----------|
| `config` | Yes | SSH and Fail2ban config files | `/your/config/path/:/config`|

## Paths/Files
There is a /stage folder that has the orginal configs. The entrypoint script will remake the /config a Volume is not need to run this docker.
The Entypoint Script has had some updates and the Docker Log will be able to explain and show issues. 
Fail2ban and sshd have ben updated and scripts/configs updated. 
If you want to make edits to sshd, fail2ban, and jails configurations as long as they exist in /config they will be deployed and used. 
A major edit was done to use the ubuntu package maintainers files and our edits to run are now using the.local file the preferred way...

Entrypoint Script will make any missing files and set correct permission for any add configs and user keys...

### SSH
| Path | Required | Function |
|----------|----------|----------|
| `/config/sshd/keys` | Yes* | SSH host keys directory |
| `/config/sshd/sshd_config` | Yes* | SSH server configuration file |
| `/config/sshd/users.conf` | Yes | SSH users config file |
| `/config/userkeys` | No | SSH user keys directory |

### Fail2Ban
| Path | Required | Function |
|----------|----------|----------|
| `/config/fail2ban` | Yes | Fail2ban config and log directory |
| `/config/fail2ban/fail2ban.local` | No* | Fail2Ban config file |
| `/config/fail2ban/jail.local` | No* | Fail2Ban jail config file |
| `/config/fail2ban/fail2ban.sqlite3` | No* | Auto generated Fail2Ban SQLite DB for persistent bans between reboots |

*These files are automatically created if they are not present when the container is started

## Ports
The OpenSSH server runs by default on port 22. You can forward the container's port 22 to any host port if using the docker bridge network and docker NAT system. 
Otherwise, you will need to edit the port in sshd_config and jails.local

| Port | Proto | Required | Function | Example |
|----------|----------|----------|----------|----------|
| `22` | TCP | Yes | SSH Port | `2222:22`|

# Customizing
## Sharing a directory from your computer
Mount the host path to a folder inside the user's home directory. Example shows mounting host upload directory to upload directory in user home folder. Alternatively, see the *bindmount dirs from another location* below for an example of mapping to a different directory and using scripts to mount dirs inside users home folders.
```
docker run \
    --cap-add=NET_ADMIN --cap-add=NET_RAW
    -v /host/config/path:/config \
    -v /host/upload:/home/user/upload \
    -p 22:22 -d bmmbmm01/sftp:latest \
    user:pass:1001
```

## Add SSH users
Add users to /config/sshd/users.conf with the following pattern:
```
user:pass:UID:GID
```

Example:
```
user:pass:1001:100
user2:abc:1002:100
user3:xyz:1003:100
```

Note: If no password is provided for the user, they can only log in using an SSH key example for user3

Example:
```
user:pass:1001:100
user2:abc:1002:100
user3::1003:100
```

## Encrypted password (Untested but should still work)
Add `:e` behind password to mark it as encrypted. Use single quotes if using a terminal instead of users config file.
```
foo:$1$0G2g0GSt$ewU0t6GXG15.0hWoOX8X9.:e:1001
```

Tip: you can use [atmoz/makepasswd](https://hub.docker.com/r/atmoz/makepasswd/) to generate encrypted passwords:  
`echo -n "your-password" | docker run -i --rm atmoz/makepasswd --crypt-md5 --clearfrom=-`

## Logging in with SSH keys
Place public keys with the user's name in /config/userkeys directory. The keys must be matched with a user's names and a .pub extension. These are copied to `.ssh/authorized_keys` for the user during container start. 

Example:
```
user.pub
```

## Providing your own SSH host key (recommended)
This container will generate new SSH host keys at first run in /config/sshd/keys. You can place your own sshd keys in this folder, and they will be copied to /etc/ssh/ when the container runs.

Tip: you can generate your keys with these commands:

```
ssh-keygen -t ed25519 -f ssh_host_ed25519_key < /dev/null
ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key < /dev/null
```

## Execute custom scripts or applications
Put your programs in `/config/sshd/scripts` and it will automatically run when the container starts.
See next subsection for an example.

### Bindmount dirs from another location
If you are using `--volumes-from` or just want to make a custom directory available in the user's home directory, you can add a script to `/config/sshd/scripts/` that bindmounts after container starts.
```
#!/bin/bash
# File mounted as: /config/sshd/scripts/bindmount.sh
# Just an example (make your own)

function bindmount() {
    if [ -d "$1" ]; then
        mkdir -p "$2"
    fi
    mount --bind $3 "$1" "$2"
}

# Remember permissions, you may have to fix them:
# chown -R :users /data/common

bindmount /data/admin-tools /home/admin/tools
bindmount /data/common /home/dave/common
bindmount /data/common /home/peter/common
bindmount /data/docs /home/peter/docs --read-only
```

**NOTE:** Using `mount` requires that your container runs with the `CAP_SYS_ADMIN` capability turned on. [See this answer for more information](https://github.com/atmoz/sftp/issues/60#issuecomment-332909232).

**Note:** The time when this image was last built can delay the availability of an OpenSSH release. Since this is an automated build linked with [phusion/baseimage](https://hub.docker.com/r/phusion/baseimage/), the build will depend on how often they push changes (out of my control). You can of course make this more predictable by cloning this repo and run your own build manually.

# Building the container yourself
To build this container, clone the repository and cd into it.

## Build it:
```
$ cd /repo/location/sftp
$ docker build -t sftp .
```
## Run it:
```
$ docker run \
    --cap-add=NET_ADMIN --cap-add=NET_RAW
    -v /host/config/path:/config \
    -p 22:22 -d bmmbmm01/sftp:latest \
    user:pass:::upload
```

This will start a container as described in the "Run container from Docker registry" section

## Using Docker Compose:
```
sftp:
    image: bmmbmm01/sftp:latest
    cap_add:
        - NET_ADMIN
        - NET_RAW
    volumes:
        - /host/upload:/home/user/upload
    ports:
        - "22:22"
    command: user:pass:::upload
```
