#!/usr/bin/env ocaml
#directory "pkg";;
#use "topkg.ml";;

let () = Pkg.describe "tlsclient" ~builder:(`OCamlbuild []) [
    Pkg.lib "pkg/META";
    Pkg.bin ~auto:true "tlsclient";
    Pkg.man ~dst:"man1/tlsclient.1" "tlsclient.1";
    Pkg.doc "README.md"; ]
