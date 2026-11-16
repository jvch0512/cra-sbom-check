module Cra.Tests

open System
open Cra.Core

let mutable passed = 0
let mutable failed = 0
let check (ok: bool) (name: string) =
    if ok then passed <- passed + 1
    else
        failed <- failed + 1
        printfn "FAIL: %s" name

let rules (text: string) = audit text "t.json" |> List.map (fun f -> f.Rule) |> List.sort
let has r text = List.contains r (rules text)
let hasNot r text = not (has r text)

let component = """{"type":"library","bom-ref":"a","name":"a","version":"1","purl":"pkg:npm/a@1","supplier":{"name":"A"},"hashes":[{"alg":"SHA-256","content":"x"}],"licenses":[{"license":{"id":"MIT"}}]}"""
let product = """{"name":"app","version":"1.0","bom-ref":"app","externalReferences":[{"type":"security-contact","url":"mailto:a@b.test"}]}"""
let bom (meta: string) (comps: string) (deps: string) =
    sprintf """{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":%s,"components":[%s],"dependencies":[%s]}""" meta comps deps
let goodMeta = sprintf """{"timestamp":"2026-11-01T00:00:00Z","authors":[{"name":"Sec"}],"component":%s}""" product
let good = bom goodMeta component """{"ref":"app","dependsOn":["a"]}"""

// clean SBOM
check (rules good = []) "complete SBOM has no findings"

// CRA001 product identity
check (has "CRA001" (bom """{"timestamp":"t","authors":[{"name":"x"}]}""" component "")) "no metadata.component"
check (has "CRA001" (bom """{"component":{"name":"app"}}""" component "")) "component without version"
check (has "CRA001" (bom """{"component":{"version":"1"}}""" component "")) "component without name"
check (hasNot "CRA001" good) "identified product"

// CRA002 timestamp, CRA003 maker
check (has "CRA002" (bom (sprintf """{"authors":[{"name":"x"}],"component":%s}""" product) component "")) "no timestamp"
check (has "CRA003" (bom (sprintf """{"timestamp":"t","component":%s}""" product) component "")) "no maker"
check (hasNot "CRA003" (bom (sprintf """{"timestamp":"t","manufacture":{"name":"Acme"},"component":%s}""" product) component "")) "manufacture name accepted"
check (hasNot "CRA003" (bom (sprintf """{"timestamp":"t","manufacturer":{"name":"Acme"},"component":%s}""" product) component "")) "manufacturer name accepted"
check (hasNot "CRA003" (bom (sprintf """{"timestamp":"t","supplier":{"name":"Acme"},"component":%s}""" product) component "")) "supplier name accepted"
check (has "CRA003" (bom (sprintf """{"timestamp":"t","authors":[],"component":%s}""" product) component "")) "empty authors array"
check (has "CRA002" (bom (sprintf """{"timestamp":"  ","authors":[{"name":"x"}],"component":%s}""" product) component "")) "blank timestamp"

// component rules
let comp (json: string) = bom goodMeta json """{"ref":"app","dependsOn":[]}"""
check (has "CRA004" (comp """{"name":"x","purl":"p","hashes":[1],"licenses":[1],"publisher":"p"}""")) "component without version"
check (has "CRA005" (comp """{"name":"x","version":"1","hashes":[1],"licenses":[1],"publisher":"p"}""")) "component without purl"
check (hasNot "CRA005" (comp """{"name":"x","version":"1","cpe":"cpe:2.3:a:x:x:1","hashes":[1],"licenses":[1],"publisher":"p"}""")) "cpe accepted instead of purl"
check (has "CRA006" (comp """{"name":"x","version":"1","purl":"p","hashes":[1],"licenses":[1]}""")) "component without supplier"
check (hasNot "CRA006" (comp """{"name":"x","version":"1","purl":"p","hashes":[1],"licenses":[1],"author":"me"}""")) "author accepted"
check (hasNot "CRA006" (comp """{"name":"x","version":"1","purl":"p","hashes":[1],"licenses":[1],"supplier":{"name":"S"}}""")) "supplier name accepted"
check (has "CRA007" (comp """{"name":"x","version":"1","purl":"p","licenses":[1],"publisher":"p"}""")) "component without hash"
check (has "CRA007" (comp """{"name":"x","version":"1","purl":"p","hashes":[],"licenses":[1],"publisher":"p"}""")) "empty hashes"
check (has "CRA009" (comp """{"name":"x","version":"1","purl":"p","hashes":[1],"publisher":"p"}""")) "component without licence"
check (rules (comp """{"name":"x","version":"1","purl":"p","hashes":[1],"licenses":[1],"publisher":"p"}""") = []) "complete component"
check (has "CRA004" (comp """{"name":"x","version":"  "}""")) "blank version"

// nested components
let nested = comp """{"name":"outer","version":"1","purl":"p","hashes":[1],"licenses":[1],"publisher":"p","components":[{"name":"inner"}]}"""
check (has "CRA004" nested) "nested component checked"
check ((audit nested "t.json" |> List.exists (fun f -> f.Where.Contains "inner"))) "nested component named in where"

// dependencies
check (has "CRA008" (bom goodMeta (component + "," + component.Replace("\"a\"", "\"b\"")) "")) "two components and no graph"
check (hasNot "CRA008" (bom goodMeta component "")) "single component needs no graph"
check (has "CRA011" (bom goodMeta component """{"ref":"app","dependsOn":["ghost"]}""")) "dependsOn unknown ref"
check (has "CRA011" (bom goodMeta component """{"ref":"ghost","dependsOn":[]}""")) "unknown ref"
check (hasNot "CRA011" good) "known refs"

// security contact
check (has "CRA010" (bom (sprintf """{"timestamp":"t","authors":[{"name":"x"}],"component":{"name":"app","version":"1"}}""") component "")) "no security contact"
check (hasNot "CRA010" (sprintf """{"bomFormat":"CycloneDX","externalReferences":[{"type":"security-contact","url":"u"}],"metadata":%s}""" goodMeta)) "top-level security contact"
check (has "CRA010" (bom (sprintf """{"timestamp":"t","authors":[{"name":"x"}],"component":{"name":"app","version":"1","externalReferences":[{"type":"website","url":"u"}]}}""") component "")) "other reference types do not count"

// CRA000
check (rules "" = [ "CRA000" ]) "empty input"
check (rules "{nope" = [ "CRA000" ]) "invalid json"
check (rules "[]" = [ "CRA000" ]) "array root"
check (rules "42" = [ "CRA000" ]) "number root"
check (rules "null" = [ "CRA000" ]) "null root"
check (rules """{"spdxVersion":"SPDX-2.3"}""" = [ "CRA000" ]) "spdx is not cyclonedx"
check (rules """{"bomFormat":"Other"}""" = [ "CRA000" ]) "other bomFormat"
check ((audit "{nope" "x.json" |> List.head).Sev = "info") "CRA000 is info"

// wrong types survive
check (not (List.isEmpty (rules """{"bomFormat":"CycloneDX","metadata":5,"components":"x","dependencies":{"a":1}}"""))) "wrong types inside a CycloneDX shell"
check (not (List.isEmpty (rules """{"bomFormat":"CycloneDX","components":[1,null,"x",{"name":5,"version":[]}],"dependencies":[1,{"ref":5,"dependsOn":[1]}]}"""))) "wrong types inside lists"

// sorting
let fs = [ { Sev = "low"; Rule = "B"; File = "a"; Where = "a"; Msg = "" }
           { Sev = "high"; Rule = "A"; File = "z"; Where = "z"; Msg = "" }
           { Sev = "high"; Rule = "A"; File = "a"; Where = "a"; Msg = "" } ]
check ((sortFindings fs |> List.map (fun f -> f.File + f.Sev)) = [ "ahigh"; "zhigh"; "alow" ]) "severity then file"

// deep nesting does not overflow
let deep = String.replicate 40 """{"name":"n","components":[""" + "{}" + String.replicate 40 "]}"
check (not (List.isEmpty (rules (bom goodMeta deep "")))) "deep component nesting"
let tooDeep = String.replicate 5000 "[" + String.replicate 5000 "]"
check (rules tooDeep = [ "CRA000" ]) "JSON deeper than the parser limit"

// fuzz
let rnd = Random(7)
let bits = [| "{"; "}"; "["; "]"; ","; ":"; "\"bomFormat\""; "\"CycloneDX\""; "\"components\""; "\"metadata\""; "\"name\""; "\"x\""; "1"; "null"; "true"; "\"dependencies\""; "\"ref\""; "\"dependsOn\"" |]
let mutable crashed = false
for _ in 1..3000 do
    let s = String.Join("", [ for _ in 1 .. rnd.Next(1, 40) -> bits.[rnd.Next bits.Length] ])
    try audit s "f.json" |> ignore with _ -> crashed <- true
    // also mutate a valid document by deleting a random slice
    let i = rnd.Next good.Length
    let j = min good.Length (i + rnd.Next 30)
    try audit (good.Remove(i, j - i)) "f.json" |> ignore with _ -> crashed <- true
check (not crashed) "3000 random and truncated inputs do not throw"

printfn "%d passed, %d failed" passed failed
exit (if failed = 0 then 0 else 1)
