import os
import json
import hashlib
import base64
import secrets
from urllib.parse import urlencode, urlparse

from flask import Flask, request, redirect, session, jsonify, make_response
import requests

# Optional: if python-dotenv is installed, load .env; otherwise run with env vars set
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
SMART_SERVER_BASE = os.environ.get('SMART_SERVER_BASE', 'https://dev.corisystem.org/smart')
FHIR_SERVER_BASE = os.environ.get('FHIR_SERVER_BASE', 'https://dev.corisystem.org/smart/fhir')
SMART_CLIENT_ID = os.environ.get('SMART_CLIENT_ID', 'simpleclient_xwxa')
SMART_REDIRECT_URI = os.environ.get('SMART_REDIRECT_URI', 'http://localhost:3005/callback')
PORT = int(os.environ.get('PORT', '3005'))

# Flask app and session config
app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', secrets.token_hex(16))
app.config['SESSION_COOKIE_NAME'] = os.environ.get('SESSION_COOKIE_NAME', 'smartclient-session')
# NOTE: For iframe usage across sites in production, ensure HTTPS and set:
# app.config['SESSION_COOKIE_SAMESITE'] = 'None'
# app.config['SESSION_COOKIE_SECURE'] = True

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def generate_pkce_pair() -> tuple[str, str]:
    code_verifier = b64url(secrets.token_urlsafe(64).encode('utf-8'))[:128]
    code_challenge = b64url(hashlib.sha256(code_verifier.encode('ascii')).digest())
    return code_verifier, code_challenge


def redact_token(token: str | None) -> str:
    if not token:
        return ''
    return f"[redacted:{token[:6]}…]"


def extract_id(value: str | None) -> str | None:
    if not value:
        return None
    # Accept raw UUID/id or absolute FHIR URL. Extract last segment.
    try:
        # If value looks like a URL with /Resource/{id} format, take the last segment
        parts = str(value).split('/')
        if len(parts) >= 2:
            return parts[-1]
        return str(value)
    except Exception:
        return None


def normalize_reference_to_cori(base: str, ref: str) -> str:
    # Ensure we never call absolute Google FHIR URLs; always call via CORI proxy base
    # Accept ref like 'Practitioner/123' or absolute URL; convert to '{base}/{type}/{id}'
    ref_str = str(ref)
    if ref_str.startswith('http://') or ref_str.startswith('https://'):
        # parse out last two segments
        segs = ref_str.rstrip('/').split('/')
        if len(segs) >= 2:
            rtype, rid = segs[-2], segs[-1]
            return f"{base.rstrip('/')}/{rtype}/{rid}"
    return f"{base.rstrip('/')}/{ref_str.strip('/')}"


def get_smart_configuration(iss_base: str) -> dict:
    conf_url = f"{iss_base.rstrip('/')}/.well-known/smart-configuration"
    print(f"Fetching SMART configuration from: {conf_url}")
    r = requests.get(conf_url, timeout=20)
    r.raise_for_status()
    data = r.json()
    print("SMART configuration:", json.dumps(data, indent=2))
    return data


def get_userinfo(userinfo_endpoint: str, access_token: str) -> dict:
    try:
        print('Fetching user info')
        r = requests.get(userinfo_endpoint, headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }, timeout=20)
        if r.status_code == 200:
            return r.json()
        print(f"Userinfo non-200: {r.status_code}")
        return {}
    except Exception as e:
        print(f"Error fetching user info: {e}")
        return {}


def get_context_value(keys: list[str], token_data: dict, userinfo_data: dict, launch_ctx: dict) -> str | None:
    for k in keys:
        if token_data.get(k):
            return token_data[k]
        if userinfo_data.get(k):
            return userinfo_data[k]
        if launch_ctx.get(k):
            return launch_ctx[k]
    return None

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@app.route('/')
def index():
    return make_response('<html><body><h2>SMART Client</h2><a href="/launch?iss=' + SMART_SERVER_BASE + '&launch=debug">Launch</a></body></html>')


@app.route('/launch')
def launch():
    iss = request.args.get('iss') or SMART_SERVER_BASE
    launch_id = request.args.get('launch')

    # Save launch context in session
    session['launchContext'] = {'iss': iss, 'launch': launch_id}
    print('Captured launch context:', session['launchContext'])

    # Discover SMART config
    smart_conf = get_smart_configuration(iss)

    # PKCE and state
    code_verifier, code_challenge = generate_pkce_pair()
    state = b64url(secrets.token_bytes(24))
    session['pkce'] = {'verifier': code_verifier, 'challenge': code_challenge}
    session['oauthState'] = state

    scope = os.environ.get('SMART_SCOPES', 'launch openid fhirUser user/*.rs')

    auth_params = {
        'response_type': 'code',
        'client_id': SMART_CLIENT_ID,
        'redirect_uri': SMART_REDIRECT_URI,
        'scope': scope,
        'state': state,
        'aud': FHIR_SERVER_BASE,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256'
    }
    if launch_id:
        auth_params['launch'] = launch_id

    auth_url = smart_conf['authorization_endpoint'] + '?' + urlencode(auth_params)
    print('Redirecting to authorization endpoint:', auth_url)
    return redirect(auth_url)


@app.route('/callback')
def callback():
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        saved_state = session.get('oauthState')
        if not state or not saved_state or state != saved_state:
            raise ValueError('Invalid state parameter. Possible CSRF attack.')

        iss = session.get('launchContext', {}).get('iss', SMART_SERVER_BASE)
        smart_conf = get_smart_configuration(iss)

        token_endpoint = smart_conf['token_endpoint']
        verifier = session.get('pkce', {}).get('verifier')
        if not verifier:
            raise ValueError('PKCE code_verifier missing in session')

        # Exchange code for token
        print(f"Exchanging authorization code for token at {token_endpoint}")
        form = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': SMART_REDIRECT_URI,
            'client_id': SMART_CLIENT_ID,
            'code_verifier': verifier,
        }
        tr = requests.post(token_endpoint, data=form, headers={'Accept': 'application/json'}, timeout=30)
        tr.raise_for_status()
        token_data = tr.json()
        redacted = dict(token_data)
        if 'access_token' in redacted:
            redacted['access_token'] = redact_token(redacted['access_token'])
        if 'refresh_token' in redacted:
            redacted['refresh_token'] = redact_token(redacted['refresh_token'])
        if 'id_token' in redacted:
            redacted['id_token'] = redact_token(redacted['id_token'])
        print('Token response:', json.dumps(redacted, indent=2))

        access_token = token_data.get('access_token')

        # Fetch Practitioner by ID
        practitioner_id = token_data.get('practitioner')
        if not practitioner_id and token_data.get('fhirUser'):
            # Extract id from fhirUser if it references Practitioner
            if 'Practitioner/' in token_data['fhirUser']:
                practitioner_id = extract_id(token_data['fhirUser'])
        if not practitioner_id:
            return make_response('No practitioner id in token', 400)

        print(f"Fetching Practitioner data for ID: {practitioner_id}")
        prac_url = f"{FHIR_SERVER_BASE.rstrip('/')}/Practitioner/{practitioner_id}"
        pr = requests.get(prac_url, headers={'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}, timeout=20)
        pr.raise_for_status()
        practitioner_data = pr.json()
        print('Successfully fetched practitioner data')

        # Enrich context: userinfo
        userinfo_data = {}
        if smart_conf.get('userinfo_endpoint'):
            userinfo_data = get_userinfo(smart_conf['userinfo_endpoint'], access_token)

        # Log contexts from CORI host
        try:
            token_context_log = dict(token_data)
            token_context_log.pop('access_token', None)
            token_context_log.pop('refresh_token', None)
            token_context_log.pop('id_token', None)
            print('Launch context (session):', session.get('launchContext') or {})
            print('Userinfo context:', userinfo_data or {})
            print('Token context (redacted):', token_context_log)
        except Exception:
            pass

        # Resolve IDs from context
        launch_ctx = session.get('launchContext') or {}
        practitioner_role_id_raw = get_context_value(
            ['practitionerRole', 'practitionerRoleId', 'role', 'roleId', 'practitioner_role_id'], token_data, userinfo_data, launch_ctx
        ) or (token_data.get('fhirUser') if token_data.get('fhirUser', '').find('PractitionerRole/') >= 0 else None)
        practitioner_role_id = extract_id(practitioner_role_id_raw)
        organization_id_raw = get_context_value(
            ['organization', 'organizationId', 'org', 'orgId', 'organization_id'], token_data, userinfo_data, launch_ctx
        )
        organization_id = extract_id(organization_id_raw)

        practitioner_roles = []
        print(f"Context PractitionerRole ID: {practitioner_role_id or 'none'}")

        headers_fhir = {'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}
        # Try PractitionerRole by _id search first
        if practitioner_role_id:
            pr_search_url = f"{FHIR_SERVER_BASE.rstrip('/')}/PractitionerRole?_id={practitioner_role_id}"
            print(f"Searching PractitionerRole by _id: {pr_search_url}")
            try:
                resp = requests.get(pr_search_url, headers=headers_fhir, timeout=20)
                if resp.status_code == 200:
                    bundle = resp.json()
                    practitioner_roles = [e['resource'] for e in bundle.get('entry', []) if 'resource' in e]
                else:
                    print(f"PractitionerRole _id search failed: HTTP {resp.status_code}")
                    print(f"Status: {resp.status_code}, Data: {resp.text}")
            except Exception as e:
                print(f"PractitionerRole _id search error: {e}")

            if not practitioner_roles:
                pr_read_url = f"{FHIR_SERVER_BASE.rstrip('/')}/PractitionerRole/{practitioner_role_id}"
                print(f"Falling back to PractitionerRole read-by-id: {pr_read_url}")
                try:
                    resp2 = requests.get(pr_read_url, headers=headers_fhir, timeout=20)
                    if resp2.status_code == 200:
                        practitioner_roles = [resp2.json()]
                    else:
                        print(f"PractitionerRole read-by-id failed: HTTP {resp2.status_code}")
                        print(f"Status: {resp2.status_code}, Data: {resp2.text}")
                except Exception as e:
                    print(f"PractitionerRole read-by-id error: {e}")

        # Fallback: search by practitioner reference
        if not practitioner_roles and practitioner_id:
            practitioner_ref = f"Practitioner/{practitioner_id}"
            pr_query_url = f"{FHIR_SERVER_BASE.rstrip('/')}/PractitionerRole?practitioner={requests.utils.quote(practitioner_ref, safe='')}"
            print(f"Searching PractitionerRole by practitioner: {pr_query_url}")
            try:
                resp3 = requests.get(pr_query_url, headers=headers_fhir, timeout=20)
                if resp3.status_code == 200:
                    bundle = resp3.json()
                    practitioner_roles = [e['resource'] for e in bundle.get('entry', []) if 'resource' in e]
                else:
                    print(f"PractitionerRole search failed: HTTP {resp3.status_code}")
                    print(f"Status: {resp3.status_code}, Data: {resp3.text}")
            except Exception as e:
                print(f"PractitionerRole practitioner search error: {e}")

        # Organization by ID if present
        organizations = []
        print('Derived context IDs:', {
            'practitionerId': practitioner_id,
            'practitionerRoleId': practitioner_role_id,
            'organizationId': organization_id
        })
        if organization_id:
            org_url = f"{FHIR_SERVER_BASE.rstrip('/')}/Organization/{organization_id}"
            print(f"Fetching Organization by id: {org_url}")
            try:
                orr = requests.get(org_url, headers=headers_fhir, timeout=20)
                if orr.status_code == 200:
                    organizations = [orr.json()]
                else:
                    print(f"Organization read-by-id failed: HTTP {orr.status_code}")
                    print(f"Status: {orr.status_code}, Data: {orr.text}")
            except Exception as e:
                print(f"Organization read-by-id error: {e}")
        else:
            print('No Organization ID found in token/userinfo/launch context')

        print(f"Collected {len(practitioner_roles)} PractitionerRole and {len(organizations)} Organization resources")

        # Render a minimal HTML summary (to keep this single-file)
        html = f"""
        <html><body>
        <h2>SMART Callback</h2>
        <h3>Practitioner</h3>
        <pre>{json.dumps(practitioner_data, indent=2)}</pre>
        <h3>PractitionerRole(s)</h3>
        <pre>{json.dumps(practitioner_roles, indent=2)}</pre>
        <h3>Organization(s)</h3>
        <pre>{json.dumps(organizations, indent=2)}</pre>
        </body></html>
        """
        return make_response(html, 200)

    except Exception as e:
        print('Error in callback:', e)
        return make_response(f"Error: {e}", 400)


# -----------------------------------------------------------------------------
# Entrypoint
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    print(f"SMART on FHIR client (Flask) running at http://localhost:{PORT}")
    print(f"Redirect URI: {SMART_REDIRECT_URI}")
    app.run(host='0.0.0.0', port=PORT, debug=True)
