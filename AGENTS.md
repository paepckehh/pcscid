# AGENTS.md

`paepcke.de/pcscid` — multiplattorm go pure, no cgo, go lib that
uses any existing pcscd service registered integrated reader to
identify any preseded card (NFC, mifare, rfid ...). There is a 
sample app for the lib api, cmd/pcscid that show in DEBUG=1 mode
a full very detailed internal debug mode, in normal mode the 
detected cardid + newline only. 

## Fixed workflow — every task, no exceptions, ALWAYS: test, commit, push! ALWAYS, DO NOT ASK!

1. **Format + check**: `gofmt, go vet, go mod tidy -check`
2. **Build**: `go build -o pcscid ./cmd/pcscid` 
3. **Test**: `make test` (to run all tests here, ensure its fully parallel).
4. **Commit**: `git add . && git commit -m '<descriptive message>'`.
5. **Tag**: bump the patch segment only, never reuse/move/delete a tag: `git tag v0.0.$(($(git describe --tags --abbrev=0 | sed 's/^v0\.0\.//')+1))`
6. **Push**: `git pull && git pull --tags && git push && git push --tags`.
