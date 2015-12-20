#!/bin/sh -x

eval `opam config env`
tlsclient www.ccc.de:443

