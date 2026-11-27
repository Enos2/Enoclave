# =============================================================================
# Project : Enoclave - private, end-to-end encrypted web chat
# File    : server/tests/day3a.ps1
# Purpose : End-to-end API test for Day 3A (invite links and join requests).
#           Creates four users and a group, then verifies: token format; the
#           invite preview; redeeming creates a pending request and is
#           idempotent; a single-use link rejects a second person; members
#           cannot create invites or see requests (403); outsiders get 404;
#           admins see the requester with their public key; approval adds the
#           member; revoked invites are rejected; denying removes the request.
#           Every line prints PASS in green or FAIL in red. Run it with:
#             powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\day3a.ps1
# =============================================================================
. "$PSScriptRoot\helpers.ps1"

$t = Get-Random -Maximum 99999
$ann = Reg "ann$t"; $bob = Reg "bob$t"; $cat = Reg "cat$t"; $dan = Reg "dan$t"

$g = Api $ann 'POST' '/groups' @{ name = 'Invite test'; members = @($bob.id); envelopes = @((Wrap $ann.id), (Wrap $bob.id)) }
$gid = $g.group.id

$inv = Api $ann 'POST' "/groups/$gid/invites" @{ ttlSeconds = 3600; maxUses = 1 }
Check 'invite token is 43 characters' $inv.token.Length 43

$pv = Api $cat 'POST' '/invites/preview' @{ token = $inv.token }
Check 'preview shows the group name' $pv.group.name 'Invite test'
Check 'preview shows the member count' $pv.group.memberCount 2

$r1 = Api $cat 'POST' '/invites/redeem' @{ token = $inv.token }
Check 'redeeming creates a pending request' $r1.status 'pending'
$r2 = Api $cat 'POST' '/invites/redeem' @{ token = $inv.token }
Check 'redeeming again stays pending' $r2.status 'pending'
Check 'single-use link rejects a second person (404)' (Code $dan 'POST' '/invites/redeem' @{ token = $inv.token }) 404

Check 'member cannot create invites (403)' (Code $bob 'POST' "/groups/$gid/invites" @{}) 403
Check 'member cannot list join requests (403)' (Code $bob 'GET' "/groups/$gid/join-requests") 403
Check 'member cannot rename the group (403)' (Code $bob 'PUT' "/groups/$gid" @{ name = 'Hacked' }) 403
Check 'outsider gets 404 on invites' (Code $dan 'GET' "/groups/$gid/invites") 404

$jr = Api $ann 'GET' "/groups/$gid/join-requests"
Check 'admin sees exactly one request' @($jr.requests).Count 1
Check 'the request is from cat' $jr.requests[0].username "cat$t"
Check 'the request carries cat public key' $jr.requests[0].publicKey.kty 'EC'

$ap = Api $ann 'POST' "/groups/$gid/join-requests/$($cat.id)/approve" @{ wrappedKey = ('A' * 64); iv = ('A' * 16) }
Check 'approve succeeds' $ap.ok True
Check 'cat is now a member' (Api $cat 'GET' "/groups/$gid").group.role 'member'

$inv2 = Api $ann 'POST' "/groups/$gid/invites" @{ ttlSeconds = 3600; maxUses = 5 }
Check 'one active invite is listed' @((Api $ann 'GET' "/groups/$gid/invites").invites).Count 1
$null = Api $ann 'DELETE' "/groups/$gid/invites/$($inv2.invite.id)"
Check 'revoked invite is rejected (404)' (Code $dan 'POST' '/invites/redeem' @{ token = $inv2.token }) 404

$inv3 = Api $ann 'POST' "/groups/$gid/invites" @{ ttlSeconds = 3600; maxUses = 5 }
$null = Api $dan 'POST' '/invites/redeem' @{ token = $inv3.token }
$null = Api $ann 'DELETE' "/groups/$gid/join-requests/$($dan.id)"
Check 'denied request disappears' @((Api $ann 'GET' "/groups/$gid/join-requests").requests).Count 0

# File: server/tests/day3a.ps1
# End of file