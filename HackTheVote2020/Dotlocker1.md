## Introduction
> We have a rogue agent trying to infiltrate our campaign. They have good opsec but we got a tip that they have some secret information uploaded on a hacker file storage site they run. Maybe we can find a way to steal that information from them and prevent more damage to our campaign.
> 
> First lets see if we can get some more information about the inner workings of the site. Its not open source but when has that stopped us.

You are provided with a link to a website (http://dotlocker.hackthe.vote/) but nothing else. You are automatically get a guest account where you can create files and save them on you account.
On the top is a navigation bar with a dropdown where you can choose from list of templates to create a new file. If your choose one, i.e. the .bashrc template you get directet to the following url: `http://dotlocker.hackthe.vote/new/etc/skel/.bashrc`

## Local File Inclusion
The `/etc/skel/.bashrc` is a path to a directory and file which exists on a typical linux system. By changing it to `/etc/passwd` we got the content of the passwd file. We tried also to access other paths like `/proc/self/cmdline` or `/etc/../proc/self/cmdline` but we got a server error or "page not found" page. This means we only have access to any file in the /etc directory.

To get more information about the system and the server they are using we look into the answer http header when accessing a page:

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 26 Oct 2020 09:29:16 GMT
Content-Type: text/html; charset=utf-8
Connection: close
Vary: Cookie
Content-Length: 2177
```
From there we see that the system uses nginx as a (probably proxy) server. Nginx has a default configuration for hosts in `/etc/nginx/sites-enabled/default` which is often also used as the active configuration file. Using the LFI exploit we are able to get the content of this config file:

```
server {
    listen 80;
    server_name _;

    location / {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $http_host;
        proxy_redirect off;

        # proxy to /server/server.py
        proxy_pass http://unix:/tmp/gunicorn.sock;
    }

    location ^~ /static  {
        include /etc/nginx/mime.types;
        alias /server/static/;
    }
}
```

The comment gives us the hint that the actual webserver is written in python and is located in `/server/server.py`. We also see that static files are servered directly by nginx from the directory `/server/static`.

## Nginx path traversal
The configuration for serving the static files is misconfigured because of a missing / at the end of `location ^~ /static` (for more information see https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/). This enables to get one directory up by using the path `/static../`. As we know from the nginx configuration the server side path is `/server/static/` and the webserver source code is in `/server/server.py`. By accessing the the page `/static../server.py` we are able to download the server.py which contains the flag as comment:

`flag{0ff_by_sl4sh_n0w_1_hav3_y0ur_sourc3}`
