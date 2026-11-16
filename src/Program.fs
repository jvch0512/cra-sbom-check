module Cra.Program

open System
open Cra.Core

let usage () =
    eprintfn "usage: cra-sbom-check PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input."
    2

let run (args: string list) : int =
    let rec parse (a: string list) (path: string option) (tsv: bool) (failOn: string option) =
        match a with
        | [] -> Ok(path, tsv, failOn)
        | "--tsv" :: r -> parse r path true failOn
        | "--fail-on" :: v :: r when v = "medium" || v = "high" || v = "critical" -> parse r path tsv (Some v)
        | "--fail-on" :: _ -> Error()
        | x :: _ when x.StartsWith "-" -> Error()
        | x :: r -> if path.IsSome then Error() else parse r (Some x) tsv failOn
    match parse args None false None with
    | Error() -> usage ()
    | Ok(None, _, _) -> usage ()
    | Ok(Some p, tsv, failOn) ->
        if not (IO.File.Exists p || IO.Directory.Exists p) then
            eprintfn "error: no such file or directory: %s" p
            2
        else
            let n, fs = auditPath (p.TrimEnd('/') |> fun x -> if x = "" then "/" else x)
            let head = sprintf "%d files, %d findings" n (List.length fs)
            let sb = Text.StringBuilder()
            sb.Append(if tsv then "# " + head else head).Append('\n') |> ignore
            for f in fs do
                if tsv then sb.Append(String.Join("\t", [ f.Sev; f.Rule; f.Where; f.Msg ])).Append('\n') |> ignore
                else
                    sb.Append(f.Sev.ToUpperInvariant().PadRight(8) + " " + f.Rule + " " + f.Where).Append('\n') |> ignore
                    sb.Append("         " + f.Msg).Append('\n') |> ignore
            Console.Out.Write(sb.ToString())
            match failOn with
            | Some l when fs |> List.exists (fun f -> rank f.Sev <= rank l) -> 1
            | _ -> 0

[<EntryPoint>]
let main argv = run (List.ofArray argv)
