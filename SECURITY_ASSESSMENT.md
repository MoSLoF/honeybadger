# HoneyBadger v2 — Full Assessment

**Date:** 2026-08-15
**Scope:** `moslof/honeybadger` @ branch `claude/full-assessment-ja7c4s`
**Target:** Flask application under `server/` and helper scripts under `util/`
**Reviewer:** Automated code & security assessment (Claude Code)

> HoneyBadger is an Active Defense / offensive-security tool: operators register
> "targets" and deploy tracking "agents" (HTML/JS/Applet/CMD) that beacon back to
> this server to geolocate whoever runs them. Because the people being tracked are
> potentially hostile and *will* interact directly with the public `/api/beacon`
> and `/demo` endpoints, robustness and hardening of those surfaces matter more
> here than in an ordinary web app.

---

## Summary

The codebase is small, readable, and well-structured for a research tool. However
it currently **will not start on any supported Python** (a hard syntax error), and
even after that is fixed it ships with **insecure default configuration** and
**no CSRF protection on destructive, GET-based, admin actions**. Several
public-facing endpoints crash on trivially malformed input, which is a
denial-of-service concern given the adversarial audience.

**Read this alongside the "Intent alignment" section below.** HoneyBadger is an
offensive / active-defense tool, so parts of its public surface are *deliberately*
weaponized. One item originally filed here (#10, demo-page XSS) is by design, and
a few others are modulated by that intent rather than being unconditional "bugs."

| # | Severity | Finding | Location |
|---|----------|---------|----------|
| 1 | Critical | `def async(...)` is a syntax error on Python ≥3.7 — app cannot import | `decorators.py:24` |
| 2 | Critical | Hardcoded `SECRET_KEY = 'development key'` → session/cookie forgery, auth bypass | `__init__.py:21` |
| 3 | High | `DEBUG = True` in committed config → Werkzeug debugger RCE + info leak | `__init__.py:20` |
| 4 | High | No CSRF protection; destructive admin actions performed over **GET** | `views.py` (multiple) |
| 5 | High | `/demo` POST dereferences `g.user` with no auth → 500 for external visitors | `views.py:218-236` |
| 6 | Medium | Password setter omits `.encode()` → every password change/activation 500s | `models.py:98` |
| 7 | Medium | Public `/api/beacon` crashes on bad `comment` / missing headers | `views.py:274-277` |
| 8 | Medium | IPStack geolocation called over cleartext HTTP (API key + target IP) | `plugins.py:29` |
| 9 | Medium | Geolocation plugins throw `TypeError` when upstream returns non-JSON | `plugins.py:42,67` |
| 10 | By design | Reflected XSS on the demo page — **intentional** agent showcase, not a defect | `templates/demo.html`, `views.py:227` |
| 11 | Low | Wi-Fi channel table 10–14 has wrong frequency ranges → wrong geolocation | `constants.py:31-35` |
| 12 | Low | No session-cookie hardening / security headers / login rate-limiting | `__init__.py`, `views.py` |
| 13 | Low | Fragile parsers raise `UnboundLocalError`/`IndexError` on malformed survey data | `parsers.py` |
| 14 | Low | `initdb` seeds demo target + beacons into the production DB | `__init__.py:52-60` |
| 15 | Info | Dead `register.html` template references a non-existent `register` endpoint | `templates/register.html:7` |

---

## Intent alignment — does fixing each item serve the tool's purpose?

Sources of intent: `README.md` ("Active Defense tool", "Example Web Agents"),
`templates/demo.html` ("XSS me, please."), and the commit history
(`fc8d8f3` always-404 for obscurity, `957304f` scenario-driven demo + CSP agent,
`922c6b8` CORS on the beacon API). The tool's mission is to **reliably collect
geolocation intelligence on a potentially hostile actor and keep that intel in the
operator's hands.** Findings are judged against that mission below.

**Intentional behavior — do NOT "fix" (a fix works *against* intent):**
- **#10 — demo-page XSS.** The `{{ text|safe }}` reflection, the `'alert(' in text`
  gate, `X-XSS-Protection: 0`, and the `window.alert` override are the delivery
  mechanism for the HTML/JavaScript/Applet/CSP agents the README documents. This
  page *is* the product; removing the XSS removes the demonstration. Reclassified
  from "Medium vulnerability" to **by design**. (The only carry-over rule: never
  copy the `|safe` pattern onto the authenticated console pages — and it isn't;
  `beacons`/`targets`/`log` all autoescape.)
- **Always-`abort(404)` on `/api/beacon`** (not filed as a bug — affirmed here so
  it is not "fixed" later): deliberate obscurity per `fc8d8f3` and both util scripts.
- **Permissive CORS on `/api/beacon`** (`@cross_origin()`, `922c6b8`): required for
  cross-origin agents to beacon back. Intentional.

**Fixes that DIRECTLY serve the mission (highest value):**
- **#1** — app won't start on Python ≥3.7; nothing matters until it runs.
- **#11** — the channel table 10–14 feeds Google's Wi-Fi geolocation; wrong ranges
  degrade the tool's core accuracy.
- **#7 / #9 / #13** — a target can crash the beacon/geolocation pipeline with
  malformed input (bad base64 `comment`, missing User-Agent, non-JSON upstream,
  fragile parser) and thereby **evade tracking**. Harden the collection path while
  keeping the intentional 404 response.

**Fixes that serve the mission by protecting the operator/console:**
- **#2 / #3 / #4 / #12** — a forgeable session, an exposed debugger, CSRF-over-GET,
  and missing headers all let an adversary the tool is tracking turn the console
  against its operator. Aligned with intent. Caveat: this is a self-hosted research
  console, so treat these as "harden before exposing it," not "the tool is broken."
  (The `X-XSS-Protection: 0` critique in #12 applies to the *console*, not to the
  demo route where the header is intentional.)

**Neutral correctness/robustness (aligned, low stakes):**
- **#5, #6, #8, #14, #15** — real defects, but fixing them neither advances nor
  conflicts with the offensive intent.

**Determination:** of 15 findings, only **#10** proposed a change that runs against
the repo's intent (now reclassified as by-design). The remaining 14 fixes either
serve the mission or are intent-neutral.

---

## Findings

### 1. (Critical) `async` used as an identifier — hard syntax error on Python ≥3.7
`decorators.py:24`
```python
def async(func):
    ...
```
`async` became a reserved keyword in Python 3.7. `views.py` imports this module,
so the import fails at load time and **the entire application fails to start** on
every currently supported Python version (repo targets "Python 3.x"; tested on
3.11):

```
$ python3 -m py_compile honeybadger/decorators.py
  File "honeybadger/decorators.py", line 24
    def async(func):
        ^^^^^  SyntaxError: invalid syntax
```

The decorator is also unused anywhere in the codebase.
**Fix:** delete the `async` decorator, or rename it (e.g. `run_async`).

---

### 2. (Critical) Hardcoded secret key → session forgery / authentication bypass
`__init__.py:21`
```python
SECRET_KEY = 'development key'
```
Flask signs the session cookie (which stores `user_id`) with this key. Because the
value is a fixed, public string in source control, anyone can forge a session
cookie for **any** `user_id` — including the admin (`role == 0`) — and take over
the console without credentials.
**Fix:** load the secret from an environment variable / secrets file and fail
closed if it is unset; generate a strong random value per deployment.

---

### 3. (High) `DEBUG = True` shipped in configuration
`__init__.py:20`
Combined with `app.run(host='0.0.0.0')` (`honeybadger.py:4`), the Werkzeug
interactive debugger is exposed on all interfaces. On an unhandled exception it
serves a traceback and an interactive console (PIN-gated but reachable) — a
remote-code-execution surface — plus source and configuration disclosure.
**Fix:** default `DEBUG = False`; drive it from an env var; never bind `0.0.0.0`
with debug on. Deploy behind a real WSGI server (gunicorn is already anticipated
in `__init__.py`).

---

### 4. (High) No CSRF protection; destructive actions performed over GET
`views.py`
State-changing operations are reachable with a simple GET and carry no CSRF token:

- `GET /beacon/delete/<int:id>` (`views.py:41`)
- `GET /target/delete/<string:guid>` (`views.py:75`)
- `GET /admin/user/<action>/<int:id>` — activate/deactivate/reset/**delete** users (`views.py:162`)
- `GET /log?clear=1` — wipes the audit log (`views.py:242`)

An authenticated admin who loads any page containing
`<img src="https://hb/target/delete/<guid>">` (or is redirected there) silently
executes the action. The POST forms (`login`, `target_add`, `profile`,
`admin_user_init`) also lack CSRF tokens. Because targets are hostile actors, an
attacker who learns a GUID can also craft cross-site requests against a logged-in
operator.
**Fix:** adopt `Flask-WTF` `CSRFProtect` (or equivalent) for all POST forms, and
convert every mutating action to POST/DELETE with a CSRF token. Never mutate state
on GET.

---

### 5. (High) `/demo` POST crashes for unauthenticated visitors
`views.py:218-236`
```python
@app.route('/demo/<string:guid>', methods=['GET', 'POST'])
def demo(guid):
    if request.method == 'POST':
        text = request.values['text']
        key = request.values['key']
        if g.user.check_password(key):   # g.user is None for external visitors
```
The demo page is meant to be visited by *targets*, who are unauthenticated, so
`g.user` is `None` and `g.user.check_password(...)` raises `AttributeError` → HTTP
500. Also `request.values['text']`/`['key']` raise `400/KeyError` when a field is
absent. The intended gate (compare against the operator's password) is not a
meaningful control on a page served to third parties.
**Fix:** guard for `g.user is None`; use `request.values.get(...)`; reconsider the
password check on a public page.

---

### 6. (Medium) Password setter omits `.encode()` — password change/activation always 500
`models.py:96-101`
```python
@password.setter
def password(self, password):
    self.password_hash = bcrypt.generate_password_hash(binascii.hexlify(password))  # str → TypeError
...
def check_password(self, password):
    return bcrypt.check_password_hash(self.password_hash, binascii.hexlify(password.encode()))
```
`binascii.hexlify` requires bytes; the setter passes a `str`:
```
TypeError: a bytes-like object is required, not 'str'
```
So `/profile` (change password) and `/profile/activate/<token>` /
`/password/reset/<token>` all crash — account activation and password change are
**completely broken**. (`initdb` works only because it happens to encode manually.)
**Fix:** `binascii.hexlify(password.encode())` in the setter, matching
`check_password`.

Side note: pre-hashing with `binascii.hexlify` doubles the input length; bcrypt
silently truncates at 72 bytes, so passwords longer than 36 characters share a
truncated hash. Consider hashing the raw UTF-8 bytes directly.

---

### 7. (Medium) Public `/api/beacon` crashes on malformed input
`views.py:274-277`
```python
comment = b64d(request.values.get('comment', '')) or None
ip       = request.environ['REMOTE_ADDR']
port     = request.environ['REMOTE_PORT']
useragent= request.environ['HTTP_USER_AGENT']
```
- `b64d('notbase64!!!')` raises `binascii.Error` → 500. Any target (or scanner)
  can trip this by sending `?comment=...` with invalid base64.
- `request.environ['HTTP_USER_AGENT']` / `['REMOTE_PORT']` raise `KeyError` when
  the header/field is absent (trivial with `curl -A ''` or a raw socket).

On the tool's most exposed, unauthenticated endpoint these are easy DoS / noisy
error paths.
**Fix:** wrap the base64 decode in try/except and reject cleanly; use
`request.environ.get(..., '')` / `request.headers.get('User-Agent', '')`.

---

### 8. (Medium) IPStack geolocation over cleartext HTTP
`plugins.py:29`
```python
url = 'http://api.ipstack.com/{0}?access_key={1}'.format(ip, app.config['IPSTACK_API_KEY'])
```
The API key and the target's IP are sent in the clear and are interceptable on
path. (Google and ipinfo already use HTTPS.)
**Fix:** use `https://`. Note IPStack's free tier historically disallowed HTTPS —
if so, prefer an HTTPS-capable provider for this leg.

---

### 9. (Medium) Geolocation plugins `TypeError` on non-JSON upstream responses
`plugins.py:42` and `plugins.py:67`
```python
if 'success' in jsondata and not jsondata['success']:   # jsondata may be None
...
if 'bogon' in jsondata and jsondata['bogon']:           # jsondata may be None
```
When the upstream returns invalid JSON, `response.json()` fails, `jsondata` stays
`None`, and the membership test raises `TypeError: argument of type 'NoneType' is
not iterable`, aborting beacon processing.
**Fix:** early-return the empty `{'lat':None,'lng':None}` when `jsondata` is falsy
before any membership/subscript access.

---

### 10. (By design) Reflected XSS on the demo page — intentional agent showcase
`templates/demo.html` + `views.py:225-227`
```python
if text and 'alert(' in text:
    text = 'Congrats! You entered: {}'.format(text)
...
{{ text|safe }}
```
**This is intended behavior, not a vulnerability to fix.** The `|safe` reflection,
the `'alert(' in text` gate, and the `X-XSS-Protection: 0` header are the delivery
mechanism for the HTML/JavaScript/Applet/CSP agents documented in the README's
"Example Web Agents" section; commit `957304f` built the page as a "scenario-driven"
agent demonstration. Removing the XSS or restoring XSS protection would defeat the
demonstration the tool exists to give. Originally filed as a Medium vulnerability;
reclassified here as **by design** after confirming intent from the README, the
template, and the commit history.

Residual (non-blocking) guidance — do these without touching the demo behavior:
- Keep the `|safe` sink confined to this demo route; never reuse it on the
  authenticated console (`beacons`/`targets`/`log` already autoescape — good).
- The operator-password gate on this page is separately broken via the `g.user`
  null-dereference (see #5); if you keep the gate, fix that crash, but the XSS
  itself should stay.

---

### 11. (Low) Wi-Fi channel frequency table is wrong for channels 10–14
`constants.py:31-35`
```python
10: range(446, 2468+1),
11: range(451, 2473+1),
12: range(456, 2478+1),
13: range(461, 2483+1),
14: range(473, 2495+1),
```
The lower bounds are missing the leading `2` (should be `2446`, `2451`, …). As
written, these ranges start near 450 and overlap everything, so `freq2channel()`
mis-maps 2.4 GHz frequencies (e.g. 2462 MHz resolves to channel 9 instead of 11).
Wrong channel numbers degrade the Google Wi-Fi geolocation accuracy the tool
depends on.
**Fix:** `10: range(2446, 2468+1)`, `11: range(2451, 2473+1)`, … `14: range(2473, 2495+1)`.

---

### 12. (Low) Missing cookie hardening, security headers, and login rate-limiting
`__init__.py`, `views.py:197-209`
- No `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY` (defaults on, but should be
  explicit), or `SESSION_COOKIE_SAMESITE='Lax'` — the last would blunt finding #4.
- No global security headers (HSTS, `X-Content-Type-Options`, frame options, a real
  CSP) on the authenticated console. (The demo route's `X-XSS-Protection: 0` is
  intentional and out of scope here — see #10; this point is about the console.)
- `/login` has no throttling/lockout → unlimited password guessing (bcrypt slows
  but does not stop it).
**Fix:** set the cookie flags and `SameSite`; add security headers app-wide
(e.g. Flask-Talisman); rate-limit `/login` (e.g. Flask-Limiter).

---

### 13. (Low) Fragile survey parsers
`parsers.py`
`parse_netsh`/`parse_iwlist` build `ap` inside a branch and reference it in later
branches; malformed input (a `Signal`/`Channel` line before its `BSSID`/`Cell`)
raises `UnboundLocalError`. `parse_airport` indexes `words[0..3]` without a length
check → `IndexError`/`ValueError`. This feeds the crash paths in #7/#9.
**Fix:** validate structure per line; skip/collect errors instead of raising; add a
few unit tests using the `*_test` fixtures already present in the file.

---

### 14. (Low) `initdb` seeds demo data into production
`__init__.py:52-60`
The initializer creates a fixed demo `Target` (well-known GUID
`aedc4c63-…-d52d32293867`) and two demo `Beacon`s, with a "remove below for
production" comment. The fixed GUID is a live, guessable target on any deployment.
**Fix:** gate demo seeding behind an explicit flag/CLI option.

---

### 15. (Info) Dead registration template
`templates/register.html:7` calls `url_for('register')`, but no `register` view
exists in `views.py`; rendering it would raise `BuildError`. Remove the template
or implement/route the endpoint intentionally.

---

## Recommended remediation order

1. **Unblock startup:** remove the `async` decorator (#1).
2. **Fix auth foundation:** external `SECRET_KEY`, `DEBUG=False` (#2, #3), then add
   CSRF + move mutations off GET (#4), and add `SameSite`/cookie flags (#12).
3. **Restore core flows:** password setter `.encode()` (#6), `/demo` null-guard (#5).
4. **Harden the public API:** safe base64/header handling (#7), plugin JSON guards
   (#9), HTTPS for IPStack (#8).
5. **Correctness & polish:** channel table (#11), parser robustness + tests (#13),
   demo seeding flag (#14), remove dead template (#15).

## Positive notes
- Passwords hashed with bcrypt; write-only `password` property prevents accidental
  read-back.
- Role checks via `@roles_required('admin')` are applied consistently to admin views.
- Parameterized ORM queries throughout — no SQL injection observed.
- Templates autoescape by default (the one `|safe` is the deliberate demo, #10).
- Tokens/GUIDs/nonces use `os.urandom`/`uuid4` (cryptographically appropriate).
- Account-activation flow deliberately `abort(404)`s on unknown tokens to avoid
  enumeration; login errors are generic.
