#!/bin/sh -x

eval `opam config env`
tlsclient -z www.ccc.de:443
tlsclient -z mirage.io:443

