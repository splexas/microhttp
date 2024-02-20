# Micro HTTP/HTTPS webserver
This is a very light HTTP/HTTPS webserver, mostly used for proxies and mitm purposes.
# How to use it
Just include `httpserver.h` in your project. However with SSL/TLS support, you must compile the project with `HTTP_SSL_TLS` directive and link it with `ssl` and `crypto` libraries. 