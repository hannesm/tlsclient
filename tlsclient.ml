
open Lwt.Infix

let indent s n =
  let padl = max 0 (n - String.length s) in
  let pad = String.make padl ' ' in
  s ^ pad

let tls_info t =
  let epoch =
    match Tls_lwt.Unix.epoch t with
    | `Ok data -> data
    | `Error -> assert false
  in
  let hex x = Hex.of_cstruct x in
  let version = Sexplib.Sexp.to_string_hum (Tls.Core.sexp_of_tls_version epoch.Tls.Core.protocol_version)
  and cipher = Sexplib.Sexp.to_string_hum (Tls.Ciphersuite.sexp_of_ciphersuite epoch.Tls.Core.ciphersuite)
  and `Hex master = hex epoch.Tls.Core.master_secret
  and pp_certs certs = List.flatten (List.map (fun x ->
      let hash = `SHA256 in
      let `Hex cert_fp = hex X509.(fingerprint hash x)
      and `Hex key_fp  = hex X509.(key_fingerprint ~hash (public_key x)) in
      [ "subject=" ^ X509.distinguished_name_to_string (X509.subject x) ;
        "issuer=" ^ X509.distinguished_name_to_string (X509.issuer x) ;
        "certificate sha256 fingerprint: " ^ cert_fp ;
        "public key sha256 fingerprint:  " ^ key_fp ^ "\n"
      ]) certs)
  and trust =
    match epoch.Tls.Core.trust_anchor with
    | None -> "NONE"
    | Some x -> X509.distinguished_name_to_string (X509.subject x)
  and pubkeysize = string_of_int (match epoch.Tls.Core.peer_certificate with
      | None -> 0
      | Some x -> match X509.public_key x with
        | `RSA p -> Nocrypto.Rsa.pub_bits p
        | _ -> 0)
  and server_time =
    let peer_random = epoch.Tls.Core.peer_random in
    let time = Cstruct.BE.get_uint32 peer_random 0 in
    let str = "raw: " ^ (Int32.to_string time) in
    match Ptime.of_float_s (Int32.to_float time) with
    | None -> str
    | Some t -> (Ptime.to_rfc3339 t) ^ " (" ^ str ^ ")"
  in
  let cert = match epoch.Tls.Core.peer_certificate with None -> [] | Some x -> [x] in
  let chain, certs = match epoch.Tls.Core.trust_anchor with
    | None -> "received", epoch.Tls.Core.received_certificates
    | Some _ -> "chain", epoch.Tls.Core.peer_certificate_chain
  in
  String.concat "\n" (List.map (fun (k, v) ->
      (indent k 9) ^ ": " ^ String.concat (indent "\n" 12) v)
      [ ("protocol", [version]) ;
        ("timestamp", [server_time]);
        ("cipher", [cipher]) ;
        ("master", [master]) ;
        ("keysize", [pubkeysize]) ;
        (chain, pp_certs certs) ;
        ("server", pp_certs cert) ;
        ("anchor", [trust]) ])

let rec read_write buf ic oc =
  Lwt.catch (fun () ->
    Lwt_io.read_into ic buf 0 4096 >>= fun l ->
    if l > 0 then
      let s = Bytes.sub buf 0 l in
      Lwt_io.write oc s >>= fun () ->
      read_write buf ic oc
    else
      Lwt.return_unit)
    (fun _ -> Lwt.return_unit)


let client zero_io trace cas cfingerprint pfingerprint starttls host port =
  begin match starttls with
  | Some "xmpp" | None -> ()
  | Some s -> failwith ("Invalid argument to --starttls: " ^ s)
  end ;
  Nocrypto_entropy_lwt.initialize () >>= fun () ->
  (match cas, cfingerprint, pfingerprint with
   | None, None, None ->
      Printf.printf "WARNING: Unauthenticated TLS connection\n" ;
      X509_lwt.authenticator `No_authentication_I'M_STUPID
   | Some _ , Some _, _
   | Some _ , _, Some _
   | _ , Some _, Some _ ->
      failwith "Error; multiple authentication methods were supplied, I cannot handle this"
   | None, Some hex_fp, None ->
      let time = Unix.gettimeofday () in
      let fp =
        Nocrypto.Uncommon.Cs.of_hex
          (String.map (function ':' -> ' ' | x -> x) hex_fp)
      in
      let fingerprints = [(host, fp)]
      and hash = `SHA256
      in
      Lwt.return (X509.Authenticator.server_cert_fingerprint ~time ~hash ~fingerprints)
   | None, None, Some hex_fp -> X509_lwt.authenticator (`Hex_key_fingerprints (`SHA256 , [(host, hex_fp)]))
   | Some ca, None, None -> X509_lwt.authenticator (`Ca_dir ca)) >>= fun authenticator ->
  Lwt.catch (fun () ->
    Lwt_unix.gethostbyname host >>= fun host_entry ->
    let host_inet_addr = Array.get host_entry.Lwt_unix.h_addr_list 0 in
    let fd = Lwt_unix.socket host_entry.Lwt_unix.h_addrtype Lwt_unix.SOCK_STREAM 0 in
    Lwt_unix.connect fd (Lwt_unix.ADDR_INET (host_inet_addr, port)) >>= fun _ ->
    (match starttls with
     | Some "xmpp" ->
        let send_lwt buf = Lwt_unix.send fd buf 0 Bytes.(length buf) [] in
        let rec recv_lwt buf offset =
          Lwt_unix.recv fd buf offset Bytes.((length buf)-offset) [] >>= fun i ->
            if i <> 50 then recv_lwt buf (offset + i) else Lwt.return 0
            (* looking for "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" *)
        in
        let read_buffer = Bytes.make 4096 '\x00'
        and starttls_buf_1 = Bytes.concat Bytes.empty [
          "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'" ;
          " xmlns='jabber:client' to='" ; host ; "' version='1.0'>" ]
        in
        send_lwt starttls_buf_1 >>= fun _ ->
        send_lwt "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>" >>= fun _ ->
        recv_lwt read_buffer 0
     | None | _ -> Lwt.return 0) >>= fun _ ->
    let client = Tls.Config.client ~authenticator () in
    let trace sexp =
      if trace then
        Printf.eprintf "%s\n\n" Sexplib.Sexp.(to_string_hum sexp)
      else
        ()
    in
    Tls_lwt.Unix.client_of_fd ~trace client ~host fd >>= fun t ->
    let tls_info = tls_info t in
    Printf.printf "%s\n%!" tls_info ;

    if zero_io then
      Lwt.return_unit
    else
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
       Lwt.return_unit)

let run_client zero_io trace cas cfingerprint pfingerprint starttls (host, port) =
  Printexc.register_printer (function
      | Tls_lwt.Tls_alert x -> Some ("TLS alert: " ^ Tls.Packet.alert_type_to_string x)
      | Tls_lwt.Tls_failure f -> Some ("TLS failure: " ^ Tls.Engine.string_of_failure f)
      | _ -> None) ;
  Sys.(set_signal sigpipe Signal_ignore) ;
  Lwt_main.run (client zero_io trace cas cfingerprint pfingerprint starttls host port)

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

let zero_io =
  let doc = "zero-I/O mode [terminate after printing session info]" in
  Arg.(value & flag & info ["z"; "zero-io"] ~doc)

let trace =
  let doc = "trace TLS session (on standard error)" in
  Arg.(value & flag & info ["t"; "trace"] ~doc)

let cfingerprint =
  let doc = "Authenticate the host's certificate using a user-supplied SHA256 fingerprint" in
  Arg.(value & opt (some string) None & info ["cert-fingerprint"] ~docv:"SHA256_HEX" ~doc)

let pfingerprint =
  let doc = "Authenticate the host's public key using a user-supplied SHA256 fingerprint" in
  Arg.(value & opt (some string) None & info ["key-fingerprint"] ~docv:"SHA256_HEX" ~doc)

let starttls =
  let doc = "Initiate connection using STARTTLS. Currently supported protocols: [xmpp]" in
  Arg.(value & opt (some string) None & info ["starttls"] ~docv:"[xmpp]" ~doc)

let cmd =
  let doc = "TLS client" in
  let man = [
    `S "DESCRIPTION" ;
    `P "$(tname) connects to a server and initiates a TLS handshake" ;
    `P "Information about the TLS session is printed, including trust anchor and chain of trust (if applicable), otherwise list of received certificates.";
    `S "BUGS" ;
    `P "Please report bugs on the issue tracker at <https://github.com/hannesm/tlsclient/issues>" ;
    `S "SEE ALSO" ;
    `P "$(b,s_client)(1)" ]
  in
  Term.(pure run_client $ zero_io $ trace $ cas $ cfingerprint $ pfingerprint $ starttls $ destination),
  Term.info "tlsclient" ~version:"0.1.0" ~doc ~man

let () =
  match Term.eval cmd
  with `Error _ -> exit 1 | _ -> exit 0
