.PHONY: build test sample

build:
	dotnet build src/CraSbom.fsproj $(RESTORE) -c Release -o build/out -v q --nologo

test: build
	dotnet run --project tests/Tests.fsproj $(RESTORE) -c Release -v q --nologo && bash tests/cli.sh

sample: build
	mkdir -p docs site
	bin/cra-sbom-check examples > docs/sample-output.txt; true
	bin/cra-sbom-check examples --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "cra-sbom-check" "Checks a CycloneDX SBOM for the minimum data the EU Cyber Resilience Act and NTIA guidance expect: product identity, timestamp, manufacturer, component versions, purls, hashes, licences, dependencies and a security contact. F#." "Synthetic data."
