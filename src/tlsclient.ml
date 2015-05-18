
open Lwt

let indent s n =
  let padl = n - String.length s in
  let pad = String.make padl ' ' in
  s ^ pad

let tls_info t =
  let open Tls.Engine in
  let epoch =
    match Tls_lwt.Unix.epoch t with
    | `Ok data -> data
    | `Error -> assert false
  in
  let version = Tls.Printer.tls_version_to_string epoch.protocol_version
  and cipher = Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite epoch.ciphersuite)
  and `Hex master = Hex.of_cstruct epoch.master_secret
  and certs = String.concat "\n" (List.map X509.to_string epoch.peer_certificate)
  and trust =
    match epoch.trust_anchor with
    | None -> "NONE"
    | Some x -> X509.to_string x
  in
  String.concat "\n" (List.map (fun (k, v) ->
      (indent k 18) ^ ": " ^ v)
      [ ("protocol", version) ;
        ("cipher", cipher) ;
        ("master secret", master) ;
        ("certificate chain", certs) ;
        ("trust anchor", trust) ])

let rec read_write buf ic oc =
  catch (fun () ->
      Lwt_io.read_into ic buf 0 4096 >>= fun l ->
      if l > 0 then
        let s = Bytes.sub buf 0 l in
        Lwt_io.write oc s >>= fun () ->
        read_write buf ic oc
      else
        return_unit)
    (fun _ -> return_unit)


let client cas host port =
  Nocrypto_entropy_lwt.initialize () >>
  X509_lwt.authenticator (match cas with
      | None -> `No_authentication_I'M_STUPID
      | Some ca -> `Ca_dir ca) >>= fun authenticator ->
  catch (fun () ->
    Tls_lwt.Unix.connect
      (Tls.Config.client ~authenticator ())
      (host, port) >>= fun t ->
    let tls_info = tls_info t in
    Printf.printf "%s\n%!" tls_info ;
    let ic, oc = Tls_lwt.of_t t in
    (* do reading and writing of stuff! *)
    let pic = Lwt_io.stdin
    and poc = Lwt_io.stdout
    in
    Lwt.join [
      read_write (Bytes.create 4096) ic poc ;
      read_write (Bytes.create 4096) pic oc
    ]
    )
    (fun exn ->
       Printf.printf "failed to establish TLS connection: %s\n" (Printexc.to_string exn) ;
       return_unit)


let run_client cas (host, port) =
  Printexc.register_printer (function
      | Tls_lwt.Tls_alert x -> Some ("TLS alert: " ^ Tls.Packet.alert_type_to_string x)
      | Tls_lwt.Tls_failure f -> Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None) ;
  Sys.(set_signal sigpipe Signal_ignore) ;
  Lwt_main.run (client cas host port)

open Cmdliner

let host_port : (string * int) Arg.converter =
  let parse s =
    try
      let open String in
      let colon = index s ':' in
      let hostname = sub s 0 colon
      and port =
        let csucc = succ colon in
        sub s csucc (length s - csucc)
      in
      `Ok (hostname, int_of_string port)
    with
      Not_found -> `Error "broken"
  in
  parse, fun ppf (h, p) -> Format.fprintf ppf "%s:%d" h p

let destination =
  Arg.(required & pos 0 (some host_port) None & info [] ~docv:"destination"
         ~doc:"the destination hostname:port to connect to")

let cas =
  Arg.(value & opt (some string) None & info ["ca"] ~docv:"FILE"
         ~doc:"The full path to PEM encoded certificate authorities. Can either be a FILE or a DIRECTORY.")


let cmd =
  let doc = "TLS client" in
  let man = [
    `S "DESCRIPTION" ;
    `P "$(tname) connects to a server and initiates a TLS handshake" ;
    `S "BUGS" ;
    `P "Please report bugs on the issue tracker at <https://github.com/hannesm/tlsclient/issues>" ;
    `S "SEE ALSO" ;
    `P "$(b,s_client)(1)" ]
  in
  Term.(pure run_client $ cas $ destination),
  Term.info "tlsclient" ~version:"0.1.0" ~doc ~man

let () =
  match Term.eval cmd
  with `Error _ -> exit 1 | _ -> exit 0
