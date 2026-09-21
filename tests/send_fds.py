# Host-side sender for tests/guests/fdimport.c: connects to a socket the guest
# bound (its HOST path) and sends the same descriptors three times — a
# directory outside the rootfs, a file outside it, and the rootfs itself, which
# the guest names "/" — one byte of data each.
import os
import socket
import sys

path, outside_dir, outside_file, inside_dir = sys.argv[1:5]
fds = [os.open(outside_dir, os.O_RDONLY | os.O_DIRECTORY),
       os.open(outside_file, os.O_RDONLY),
       os.open(inside_dir, os.O_RDONLY | os.O_DIRECTORY)]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(path)
socket.send_fds(s, [b"a"], fds)
socket.send_fds(s, [b"b"], fds)
socket.send_fds(s, [b"c"], fds)
s.close()
