module Cra.Core

open System
open System.IO
open System.Text.Json

type Finding = { Sev: string; Rule: string; File: string; Where: string; Msg: string }

let rank sev =
    match sev with
    | "critical" -> 0
    | "high" -> 1
    | "medium" -> 2
    | "low" -> 3
    | _ -> 4

let private mk sev rule file where msg = { Sev = sev; Rule = rule; File = file; Where = where; Msg = msg }

let private prop (el: JsonElement) (name: string) : JsonElement option =
    if el.ValueKind = JsonValueKind.Object then
        match el.TryGetProperty name with
        | true, v -> Some v
        | _ -> None
    else None

let private str (e: JsonElement option) : string =
    match e with
    | Some v when v.ValueKind = JsonValueKind.String -> v.GetString().Trim()
    | _ -> ""

let private items (e: JsonElement option) : JsonElement list =
    match e with
    | Some v when v.ValueKind = JsonValueKind.Array -> [ for x in v.EnumerateArray() -> x ]
    | _ -> []

let private nonEmptyArray e = not (List.isEmpty (items e))

let rec private flatten (depth: int) (comps: JsonElement list) : JsonElement list =
    if depth > 50 then comps
    else
        comps
        |> List.collect (fun c ->
            if c.ValueKind <> JsonValueKind.Object then []
            else c :: flatten (depth + 1) (items (prop c "components")))

let private label (c: JsonElement) =
    let n = str (prop c "name")
    let v = str (prop c "version")
    let n2 = if n = "" then "(unnamed)" else n
    if v = "" then n2 else n2 + "@" + v

let audit (text: string) (file: string) : Finding list =
    try
        use doc = JsonDocument.Parse(text)
        let root = doc.RootElement
        if root.ValueKind <> JsonValueKind.Object || str (prop root "bomFormat") <> "CycloneDX" then
            [ mk "info" "CRA000" file file "not a CycloneDX JSON document, ignored" ]
        else
            let out = ResizeArray<Finding>()
            let add sev rule where msg = out.Add(mk sev rule file (file + "#" + where) msg)
            let meta = prop root "metadata"
            let metaEl = defaultArg meta (JsonDocument.Parse("{}").RootElement)
            let product = prop metaEl "component"
            let pname = match product with Some p -> str (prop p "name") | None -> ""
            let pver = match product with Some p -> str (prop p "version") | None -> ""
            if pname = "" || pver = "" then
                add "high" "CRA001" "metadata.component" "the product is not identified: metadata.component needs a name and a version"
            if str (prop metaEl "timestamp") = "" then
                add "medium" "CRA002" "metadata" "no timestamp: nobody can tell how fresh this SBOM is"
            let hasMaker =
                nonEmptyArray (prop metaEl "authors")
                || str (prop (defaultArg (prop metaEl "manufacture") (JsonDocument.Parse("{}").RootElement)) "name") <> ""
                || str (prop (defaultArg (prop metaEl "manufacturer") (JsonDocument.Parse("{}").RootElement)) "name") <> ""
                || str (prop (defaultArg (prop metaEl "supplier") (JsonDocument.Parse("{}").RootElement)) "name") <> ""
            if not hasMaker then
                add "medium" "CRA003" "metadata" "no author, manufacturer or supplier of the SBOM"
            let securityContact (e: JsonElement option) =
                items e |> List.exists (fun r -> str (prop r "type") = "security-contact")
            let hasContact =
                securityContact (prop root "externalReferences")
                || (match product with Some p -> securityContact (prop p "externalReferences") | None -> false)
            if not hasContact then
                add "medium" "CRA010" "externalReferences" "no external reference of type security-contact for vulnerability reports"
            let comps = flatten 0 (items (prop root "components"))
            for c in comps do
                let l = label c
                let w = "components[" + l + "]"
                if str (prop c "version") = "" then add "medium" "CRA004" w (l + " has no version")
                if str (prop c "purl") = "" && str (prop c "cpe") = "" then add "medium" "CRA005" w (l + " has no purl or CPE, so it cannot be matched to advisories")
                let hasSupplier =
                    str (prop (defaultArg (prop c "supplier") (JsonDocument.Parse("{}").RootElement)) "name") <> ""
                    || str (prop c "publisher") <> ""
                    || str (prop c "author") <> ""
                if not hasSupplier then add "low" "CRA006" w (l + " has no supplier, publisher or author")
                if not (nonEmptyArray (prop c "hashes")) then add "low" "CRA007" w (l + " has no hash")
                if not (nonEmptyArray (prop c "licenses")) then add "low" "CRA009" w (l + " has no licence information")
            let deps = items (prop root "dependencies")
            if List.isEmpty deps && List.length comps > 1 then
                add "medium" "CRA008" "dependencies" "no dependency graph: it is unclear which component pulls in which"
            let refs =
                (comps |> List.map (fun c -> str (prop c "bom-ref")) |> List.filter (fun r -> r <> ""))
                @ (match product with Some p -> [ str (prop p "bom-ref") ] | None -> [])
                |> Set.ofList
            for d in deps do
                let r = str (prop d "ref")
                if r <> "" && not (Set.contains r refs) then
                    add "low" "CRA011" ("dependencies[" + r + "]") ("dependency entry refers to unknown bom-ref " + r)
                for t in items (prop d "dependsOn") do
                    if t.ValueKind = JsonValueKind.String && not (Set.contains (t.GetString()) refs) then
                        add "low" "CRA011" ("dependencies[" + r + "]") (r + " depends on unknown bom-ref " + t.GetString())
            List.ofSeq out
    with
    | :? JsonException -> [ mk "info" "CRA000" file file "not valid JSON, ignored" ]
    | :? ArgumentException -> [ mk "info" "CRA000" file file "not valid JSON, ignored" ]

let sortFindings (fs: Finding list) : Finding list =
    fs |> List.sortWith (fun a b ->
        let c = compare (rank a.Sev) (rank b.Sev)
        if c <> 0 then c
        else
            let c2 = String.CompareOrdinal(a.File, b.File)
            if c2 <> 0 then c2
            else
                let c3 = String.CompareOrdinal(a.Rule, b.Rule)
                if c3 <> 0 then c3 else String.CompareOrdinal(a.Where, b.Where))

let rec private walk (dir: string) (root: string) (depth: int) : (string * string) list =
    if depth > 30 then []
    else
        let files =
            try Directory.GetFiles(dir, "*.json") |> Array.sortWith (fun a b -> String.CompareOrdinal(a, b)) |> List.ofArray
            with _ -> []
        let dirs =
            try Directory.GetDirectories(dir) |> Array.sortWith (fun a b -> String.CompareOrdinal(a, b)) |> List.ofArray
            with _ -> []
        let here =
            files
            |> List.filter (fun f -> (FileInfo(f)).Attributes &&& FileAttributes.ReparsePoint = enum 0)
            |> List.map (fun f -> (Path.GetRelativePath(root, f).Replace('\\', '/'), f))
        let sub =
            dirs
            |> List.filter (fun d ->
                let n = Path.GetFileName d
                n <> ".git" && n <> "node_modules" && (DirectoryInfo(d)).Attributes &&& FileAttributes.ReparsePoint = enum 0)
            |> List.collect (fun d -> walk d root (depth + 1))
        here @ sub

let auditPath (path: string) : int * Finding list =
    let files =
        if Directory.Exists path then walk path path 0
        else [ (Path.GetFileName path, path) ]
    let all =
        files
        |> List.collect (fun (label, f) ->
            let text = try (if FileInfo(f).Length > 50_000_000L then "" else File.ReadAllText f) with _ -> ""
            audit text label)
    (List.length files, sortFindings all)
