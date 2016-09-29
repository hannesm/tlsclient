#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "tlsclient" @@ fun _c ->
  Ok [ Pkg.bin "tlsclient" ]
