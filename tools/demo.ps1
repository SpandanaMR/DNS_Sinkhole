# DNS Sinkhole Demo Script
# Run from PowerShell with the virtual environment activated.
# Usage: .\tools\demo.ps1

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DNS Sinkhole / Caching Resolver - Live Demo" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Check prerequisites
Write-Host "[0] Checking Python..." -ForegroundColor Yellow
python --version
Write-Host ""

# Step 1: Start the server in the background
Write-Host "[1] Starting DNS Sinkhole server on port 5353..." -ForegroundColor Yellow
$serverJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    python -m dnssink --port 5353 --config config.toml
}
Start-Sleep -Seconds 2
Write-Host "    Server started (Job ID: $($serverJob.Id))" -ForegroundColor Green
Write-Host ""

# Step 2: Normal query (cache miss -> forwarded)
Write-Host "[2] Query: example.com A (should be FORWARDED)" -ForegroundColor Yellow
python tools/dnsclient.py example.com A --port 5353
Write-Host ""

# Step 3: Same query again (cache hit)
Write-Host "[3] Query: example.com A again (should be CACHE_HIT, lower latency)" -ForegroundColor Yellow
python tools/dnsclient.py example.com A --port 5353
Write-Host ""

# Step 4: Blocked domain
Write-Host "[4] Query: example-ads.test A (should be BLOCKED -> 0.0.0.0)" -ForegroundColor Yellow
python tools/dnsclient.py example-ads.test A --port 5353
Write-Host ""

# Step 5: Blocked subdomain
Write-Host "[5] Query: sub.tracker.example-ads.test A (subdomain also BLOCKED)" -ForegroundColor Yellow
python tools/dnsclient.py sub.tracker.example-ads.test A --port 5353
Write-Host ""

# Step 6: AAAA query
Write-Host "[6] Query: google.com AAAA" -ForegroundColor Yellow
python tools/dnsclient.py google.com AAAA --port 5353
Write-Host ""

# Step 7: TCP query
Write-Host "[7] Query: example.com A via TCP" -ForegroundColor Yellow
python tools/dnsclient.py example.com A --port 5353 --tcp
Write-Host ""

# Step 8: Dashboard
Write-Host "[8] Dashboard is available at: http://127.0.0.1:8080" -ForegroundColor Yellow
Write-Host "    Open in browser to see live stats." -ForegroundColor Gray
Write-Host ""

# Step 9: Quick load test
Write-Host "[9] Running quick load test (10 clients x 500 queries)..." -ForegroundColor Yellow
python tools/loadtest.py --clients 10 --queries 500 --mode cache
Write-Host ""

# Step 10: nslookup note
Write-Host "[10] nslookup: Windows 11 nslookup ignores -port and always uses port 53." -ForegroundColor Yellow
Write-Host "     To demo it, start the server with --port 53, then: nslookup example.com 127.0.0.1" -ForegroundColor Gray
Write-Host ""

# Cleanup
Write-Host "[!] Demo complete. Stopping server..." -ForegroundColor Cyan
Stop-Job $serverJob -ErrorAction SilentlyContinue
Remove-Job $serverJob -ErrorAction SilentlyContinue -Force
Write-Host "    Server stopped." -ForegroundColor Green
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Demo finished!" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
