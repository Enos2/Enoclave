# =============================================================================
# Project : Enoclave - private, end-to-end encrypted web chat
# File    : server/tests/helpers.ps1
# Purpose : Shared helpers for the PowerShell API tests, loaded by each test
#           script. Provides: Reg (create a test user and keep its session
#           cookie), Api (call the API as a user and return the parsed JSON),
#           Code (call the API and return only the HTTP status code, used to
#           assert that forbidden or invalid requests are rejected), Wrap (a
#           dummy group-key envelope: the server never inspects the contents),
#           and Check (print a green PASS or red FAIL line). Test users get
#           random names, so the tests can be run repeatedly.
#           Note: registration is limited to 20 per hour per network; if you
#           see 429 on registering, restart the server (the counter is in memory).
# =============================================================================
$h   = @{ Origin = 'http://localhost:5173' }
$api = 'http://localhost:5000/api'
$k   = @{ kty = 'EC'; crv = 'P-256'; x = ('A' * 43); y = ('B' * 43) }

function Reg($n) {
  $b = @{ username = $n; password = 'correct-horse-battery'; publicKey = $k } | ConvertTo-Json
  $r = Invoke-RestMethod "$api/auth/register" -Method Post -Headers $h -ContentType 'application/json' -Body $b -SessionVariable s
  return @{ id = $r.user.id; s = $s }
}

function Api($u, $m, $p, $body) {
  $a = @{ Uri = "$api$p"; Method = $m; Headers = $h; WebSession = $u.s }
  if ($null -ne $body) { $a.ContentType = 'application/json'; $a.Body = ($body | ConvertTo-Json -Depth 6) }
  Invoke-RestMethod @a
}

function Code($u, $m, $p, $body) {
  try { Api $u $m $p $body | Out-Null; return 200 }
  catch { return $_.Exception.Response.StatusCode.value__ }
}

function Wrap($id) { @{ userId = $id; wrappedKey = ('A' * 64); iv = ('A' * 16) } }

function Check($label, $actual, $expected) {
  if ("$actual" -eq "$expected") { Write-Host "PASS  $label" -ForegroundColor Green }
  else { Write-Host "FAIL  $label (got '$actual', expected '$expected')" -ForegroundColor Red }
}

# File: server/tests/helpers.ps1
# End of file