# Build Troubleshooting Guide

## Quick Fix

If you got compilation errors, the files have been updated. Simply re-download all the `.go` files and run:

```bash
chmod +x build.sh
./build.sh
```

## Common Errors and Fixes

### Error: "min redeclared in this block"

**Fixed!** The `min` function was renamed to `minInt` in both `service_detection.go` and `scripts_webapp.go`.

### Error: "undefined: RDPSecurityScript" (and similar)

**This means the files aren't being compiled together.** 

Make sure ALL these files are in the same directory:
- main.go
- types.go
- scanner.go
- utils.go
- service_detection.go
- script_engine.go
- scripts_http.go
- scripts_services.go
- scripts_database.go
- scripts_smb.go
- scripts_windows.go
- scripts_enumeration.go
- scripts_webapp.go

Then run: `go build -o gomap .`

The `.` at the end is important - it tells Go to compile all `.go` files in the current directory.

### Error: "package main is not in GOROOT"

Make sure you're in the directory containing all the `.go` files:
```bash
cd /path/to/gomap
ls *.go  # Should show all 13 files
go build -o gomap .
```

### Error: "go: cannot find main module"

You don't need a `go.mod` for this project, but if Go insists:
```bash
go mod init gomap
go build -o gomap .
```

### Error: Go version too old

You need Go 1.21 or later:
```bash
go version  # Should show 1.21 or higher
```

If too old, update from https://golang.org/dl/

## Verification Steps

1. **Count your files:**
   ```bash
   ls *.go | wc -l
   # Should output: 13
   ```

2. **Check all files are in main package:**
   ```bash
   grep "package main" *.go | wc -l
   # Should output: 13
   ```

3. **Verify script types exist:**
   ```bash
   grep "type.*Script struct" scripts_*.go | wc -l
   # Should output: 52 (one for each script)
   ```

## Manual Build Process

If the automatic build fails, try these steps:

```bash
# Clean any old builds
rm -f gomap

# Format all Go files
go fmt *.go

# Check for syntax errors
go vet *.go

# Build with verbose output
go build -v -o gomap .

# If it works, test it
./gomap -script-help
```

## Still Having Issues?

### Check File Integrity

```bash
# Each file should have these approximate line counts:
wc -l *.go
```

Expected output:
```
  90 main.go
  30 types.go
 210 scanner.go
 110 utils.go
 200 service_detection.go
 240 script_engine.go
 230 scripts_http.go
 150 scripts_services.go
 300 scripts_database.go
 230 scripts_smb.go
 265 scripts_windows.go
 295 scripts_enumeration.go
 395 scripts_webapp.go
```

### Rebuild from Scratch

```bash
# Remove everything
rm *.go gomap

# Re-download ALL files
# Make sure you get all 13 .go files

# Then build
go build -o gomap .
```

## Success Indicators

When the build succeeds, you should see:
```bash
$ ./gomap -script-help


   ██████╗  ██████╗ ███╗   ███╗ █████╗ ██████╗ 
  ██╔════╝ ██╔═══██╗████╗ ████║██╔══██╗██╔══██╗
  ██║  ███╗██║   ██║██╔████╔██║███████║██████╔╝
  ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
  ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     
   ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     

          Network Scanner & Exploitation Tool
          ═══════════════════════════════════════

Available Scripts:
==================

auth Scripts:
  - http-auth: Detects HTTP authentication methods
  - ftp-anon: Checks for anonymous FTP login
  [... etc ...]
```

## Getting Help

If you're still stuck:
1. Make sure you have Go 1.21+
2. Make sure ALL 13 .go files are present
3. Try the manual build process above
4. Check that files weren't corrupted during download

## Quick Test After Build

```bash
# Test the scanner works
./gomap -target scanme.nmap.org -ports 80,443 -script

# Should show open ports and run scripts
```
