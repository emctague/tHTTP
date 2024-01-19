# tHTTP

tHTTP is a tiny C HTTP server written to run on macOS.

It's intended to be small and easy to audit for security.

It reads all serve-able files into memory at startup and then abandons all privileges except for the
ability to fork(). Each client connection is handled in a forked process. Request headers
and body aren't parsed at all.

Distributed under the MIT license.
