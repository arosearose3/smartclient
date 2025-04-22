/**
 * SMART on FHIR Client
 * A simple Express server that demonstrates SMART App launch flow
 */

import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import axios from 'axios';
import { URL } from 'url';
import path from 'path';
import { fileURLToPath } from 'url';

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const PORT = 3005;
const CLIENT_ID = 'simpleclient_xwxa'; // Your registered client ID with localhost redirect URIs
const SMART_SERVER_BASE = 'https://corisystem.org/onecred/smart';
const FHIR_SERVER_BASE = 'https://corisystem.org/onecred/smart/fhir';
const REDIRECT_URI = `http://localhost:${PORT}/smart/callback`;

// Create Express app
const app = express();

// Configure sessions for storing PKCE and state values
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Use secure: true in production with HTTPS
}));

// Set the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Create the views directory and templates
import fs from 'fs';
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) {
  fs.mkdirSync(viewsDir);
}

// Create EJS templates
const indexTemplate = `
<!DOCTYPE html>
<html>
<head>
  <title>SMART on FHIR Client</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }
    .container { border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-top: 20px; }
    button { background: #4CAF50; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
    h1, h2 { color: #333; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>SMART on FHIR Client</h1>
  <div class="container">
    <p>Click the button below to launch the SMART App and retrieve practitioner data:</p>
    <button onclick="window.location.href='/launch'">Launch SMART App</button>
  </div>
</body>
</html>
`;

const callbackTemplate = `
<!DOCTYPE html>
<html>
<head>
  <title>SMART on FHIR Client - User Data</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f9f9f9; }
    .container { border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-top: 20px; background: white; }
    .success { color: #4CAF50; }
    .error { color: #f44336; }
    h1, h2, h3 { color: #333; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    button { background: #4CAF50; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
    a { color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
    
    /* Practitioner Card Styles */
    .practitioner-card {
      background: white;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      padding: 20px;
      margin-bottom: 30px;
      max-width: 600px;
      margin-left: auto;
      margin-right: auto;
    }
    
    .practitioner-header {
      display: flex;
      align-items: center;
      margin-bottom: 20px;
    }
    
    .practitioner-avatar {
      width: 80px;
      height: 80px;
      border-radius: 50%;
      background: #3949ab;
      color: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 36px;
      font-weight: bold;
      margin-right: 20px;
      flex-shrink: 0;
    }
    
    .practitioner-info {
      flex-grow: 1;
    }
    
    .practitioner-name {
      margin: 0 0 5px 0;
      font-size: 24px;
      color: #333;
    }
    
    .practitioner-specialty {
      color: #666;
      font-size: 16px;
    }
    
    .practitioner-details {
      border-top: 1px solid #eee;
      padding-top: 15px;
    }
    
    .detail-item {
      display: flex;
      align-items: center;
      margin-bottom: 10px;
    }
    
    .detail-icon {
      width: 30px;
      font-size: 18px;
      margin-right: 10px;
    }
    
    .detail-text {
      color: #444;
    }
    
    /* Organization Card Styles */
    .org-cards { display: flex; flex-wrap: wrap; gap: 15px; margin-bottom: 20px; }
    .org-card { 
      border: 1px solid #ddd; 
      border-radius: 8px; 
      padding: 15px; 
      width: 200px; 
      box-shadow: 0 3px 6px rgba(0,0,0,0.1);
      background: #fff;
      transition: transform 0.3s ease;
    }
    .org-card:hover { transform: translateY(-5px); box-shadow: 0 6px 12px rgba(0,0,0,0.1); }
    .org-name { font-weight: bold; font-size: 1.1em; margin-bottom: 5px; }
    .org-type { color: #666; font-size: 0.9em; margin-bottom: 10px; }
    .org-address { font-size: 0.85em; color: #444; }
    .org-roles { margin-top: 10px; font-size: 0.8em; color: #555; }
    .role-badge { 
      display: inline-block; 
      background: #e9f7fe; 
      padding: 3px 8px; 
      border-radius: 12px; 
      margin-right: 5px;
      margin-bottom: 5px;
      font-size: 0.85em;
    }
  </style>
</head>
<body>
  <h1>SMART on FHIR Client - User Data</h1>
  
  <% if (error) { %>
    <div class="container">
      <h2 class="error">Error</h2>
      <p><%= error %></p>
    </div>
  <% } else { %>
    <!-- Organization Cards at the top -->
    <!-- Practitioner Information Card -->
    <div class="practitioner-card">
      <% if (practitionerData && practitionerData._formatted) { %>
        <div class="practitioner-header">
          <div class="practitioner-avatar">
            <%= practitionerData._formatted.name.charAt(0).toUpperCase() %>
          </div>
          <div class="practitioner-info">
            <h2 class="practitioner-name"><%= practitionerData._formatted.name %></h2>
            <div class="practitioner-specialty"><%= practitionerData._formatted.specialty %></div>
          </div>
        </div>
        <div class="practitioner-details">
          <div class="detail-item">
            <span class="detail-icon">✉️</span>
            <span class="detail-text"><%= practitionerData._formatted.email %></span>
          </div>
          <div class="detail-item">
            <span class="detail-icon">📞</span>
            <span class="detail-text"><%= practitionerData._formatted.phone %></span>
          </div>
          <div class="detail-item">
            <span class="detail-icon">🆔</span>
            <span class="detail-text"><%= practitionerData.id %></span>
          </div>
        </div>
      <% } else { %>
        <div class="practitioner-header">
          <div class="practitioner-avatar">?</div>
          <div class="practitioner-info">
            <h2 class="practitioner-name">Practitioner</h2>
            <div class="practitioner-specialty">No details available</div>
          </div>
        </div>
      <% } %>
    </div>
    
    <!-- Organization Cards -->
    <% if (organizations && organizations.length > 0) { %>
      <h2>Organizations (<%= organizations.length %>)</h2>
      <div class="org-cards">
        <% organizations.forEach(org => { %>
          <div class="org-card">
            <div class="org-name"><%= org.name %></div>
            <div class="org-type"><%= org.type?.[0]?.text || 'Organization' %></div>
            <% if (org.address && org.address.length > 0) { %>
              <div class="org-address">
                <%= org.address[0].city || '' %><%= org.address[0].city && org.address[0].state ? ', ' : '' %><%= org.address[0].state || '' %>
              </div>
            <% } %>
            <div class="org-roles">
              <% 
                const orgRoles = practitionerRoles.filter(role => 
                  role.organization && 
                  role.organization.reference && 
                  role.organization.reference.includes(org.id)
                );
                
                orgRoles.forEach(role => { 
                  if (role.code && role.code.length > 0 && role.code[0].text) { 
              %>
                <span class="role-badge"><%= role.code[0].text %></span>
              <% } }); %>
            </div>
          </div>
        <% }); %>
      </div>
    <% } %>
    
    <div class="container">
      <h2 class="success">Authentication Successful</h2>
      <p>Successfully authenticated with the SMART server!</p>
      
      <h3>Practitioner Data</h3>
      <pre><%= JSON.stringify(practitionerData, null, 2) %></pre>
      
      <h3>Access Token</h3>
      <pre><%= JSON.stringify(tokenResponse, null, 2) %></pre>
      
      <h3>PractitionerRole Data</h3>
      <pre><%= JSON.stringify(practitionerRoles, null, 2) %></pre>
      
      <h3>FHIR User Data</h3>
      <pre><%= JSON.stringify(fhirUserData, null, 2) %></pre>
      
      <h3>SMART Well-Known Configuration</h3>
      <pre><%= JSON.stringify(fhirUserData?.context?.system?.smartConfiguration || 'Not available', null, 2) %></pre>
      
      <p><a href="/">Back to home</a></p>
    </div>
  <% } %>
  
</body>
</html>
`;

// Write templates to files
fs.writeFileSync(path.join(viewsDir, 'index.ejs'), indexTemplate);
fs.writeFileSync(path.join(viewsDir, 'callback.ejs'), callbackTemplate);

// Routes
app.get('/', (req, res) => {
  res.render('index');
});

// SMART App Launch
app.get('/launch', async (req, res) => {
  try {
    // Generate PKCE challenge
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    
    // Generate random state parameter for CSRF protection
    const state = crypto.randomBytes(16).toString('hex');
    
    // Store PKCE verifier and state in session
    req.session.codeVerifier = codeVerifier;
    req.session.state = state;
    
    // Capture any launch context parameters
    const launchContext = {};
    for (const [key, value] of Object.entries(req.query)) {
      launchContext[key] = value;
    }
    
    // If there are launch parameters, store them in the session
    if (Object.keys(launchContext).length > 0) {
      console.log('Captured launch context:', launchContext);
      req.session.launchContext = launchContext;
    }
    
    // Fetch .well-known/smart-configuration to discover authorization endpoint
    console.log('Fetching SMART configuration...');
    const smartConfigResponse = await axios.get(`${SMART_SERVER_BASE}/.well-known/smart-configuration`);
    const smartConfig = smartConfigResponse.data;
    console.log('SMART configuration:', smartConfig);
    
    // Construct authorization URL
    const authorizationEndpoint = smartConfig.authorization_endpoint;
    
    // Build authorization request URL
    const authUrl = new URL(authorizationEndpoint);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('client_id', CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.append('scope', 'launch openid fhirUser user/*.rs');
    authUrl.searchParams.append('state', state);
    authUrl.searchParams.append('aud', FHIR_SERVER_BASE);
    authUrl.searchParams.append('code_challenge', codeChallenge);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    
    // Redirect to authorization server
    console.log(`Redirecting to authorization endpoint: ${authUrl.toString()}`);
    res.redirect(authUrl.toString());
  } catch (error) {
    console.error('Error initiating SMART launch:', error);
    res.status(500).send(`Error initiating SMART launch: ${error.message}`);
  }
});

// OAuth Callback
app.get('/smart/callback', async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;
    
    // Check for authorization errors
    if (error) {
      throw new Error(`Authorization error: ${error} - ${error_description}`);
    }
    
    // Validate state to prevent CSRF
    if (state !== req.session.state) {
      throw new Error('Invalid state parameter. Possible CSRF attack.');
    }
    
    // Retrieve code verifier from session
    const codeVerifier = req.session.codeVerifier;
    if (!codeVerifier) {
      throw new Error('Code verifier not found in session');
    }
    
    // Fetch .well-known/smart-configuration to discover token endpoint
    const smartConfigResponse = await axios.get(`${SMART_SERVER_BASE}/.well-known/smart-configuration`);
    const tokenEndpoint = smartConfigResponse.data.token_endpoint;
    
    console.log(`Exchanging authorization code for token at ${tokenEndpoint}`);
    
    // Exchange authorization code for token
    const tokenResponse = await axios.post(tokenEndpoint, new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier
    }), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    
    const tokenData = tokenResponse.data;
    console.log('Token response:', tokenData);
    
    // Use the token to fetch Practitioner data and related resources
    let practitionerData = null;
    let fhirUserData = null;
    let practitionerRoles = [];
    let organizations = [];
    
    if (tokenData.access_token) {
      try {
        // Extract the practitioner ID from the token response
        const practitionerId = tokenData.practitioner;
        
        if (practitionerId) {
          console.log(`Fetching Practitioner data for ID: ${practitionerId}`);
          
          // Use the SMART server's FHIR proxy to fetch the practitioner
          const practitionerResponse = await axios.get(`${FHIR_SERVER_BASE}/Practitioner/${practitionerId}`, {
            headers: {
              'Authorization': `Bearer ${tokenData.access_token}`,
              'Accept': 'application/json'
            }
          });
          
          practitionerData = practitionerResponse.data;
          console.log('Successfully fetched practitioner data');
          
          // Try fetching PractitionerRole resources
          try {
            console.log(`Fetching PractitionerRole resources for practitioner: ${practitionerId}`);
            const practitionerRoleResponse = await axios.get(
              `${FHIR_SERVER_BASE}/PractitionerRole?practitioner=${practitionerId}`,
              {
                headers: {
                  'Authorization': `Bearer ${tokenData.access_token}`,
                  'Accept': 'application/json'
                }
              }
            );
            
            if (practitionerRoleResponse.data && practitionerRoleResponse.data.entry) {
              practitionerRoles = practitionerRoleResponse.data.entry.map(entry => entry.resource);
              console.log(`Found ${practitionerRoles.length} PractitionerRole resources`);
              
              // Extract unique organization references
              const orgReferences = [];
              practitionerRoles.forEach(role => {
                if (role.organization && role.organization.reference) {
                  const orgRef = role.organization.reference;
                  if (!orgReferences.includes(orgRef)) {
                    orgReferences.push(orgRef);
                  }
                }
              });
              
              // Fetch each organization
              for (const orgRef of orgReferences) {
                const orgId = orgRef.split('/').pop();
                try {
                  console.log(`Fetching organization: ${orgId}`);
                  const orgResponse = await axios.get(
                    `${FHIR_SERVER_BASE}/Organization/${orgId}`,
                    {
                      headers: {
                        'Authorization': `Bearer ${tokenData.access_token}`,
                        'Accept': 'application/json'
                      }
                    }
                  );
                  
                  if (orgResponse.data) {
                    organizations.push(orgResponse.data);
                  }
                } catch (orgError) {
                  console.log(`Error fetching organization ${orgId}: ${orgError.message}`);
                  if (orgError.response) {
                    console.log(`Status: ${orgError.response.status}, Data: ${JSON.stringify(orgError.response.data).substring(0, 100)}...`);
                  }
                }
              }
              
              console.log(`Fetched ${organizations.length} organizations`);
            }
          } catch (roleError) {
            console.log(`Error fetching PractitionerRole resources: ${roleError.message}`);
            if (roleError.response) {
              console.log(`Status: ${roleError.response.status}, Data: ${roleError.response.data}`);
            }
            console.log('Continuing without PractitionerRole and Organization data');
          }
          
          // Display practitioner information card
          const practitionerInfo = {
            name: 'Unknown',
            email: 'No email available',
            phone: 'No phone available',
            specialty: 'Unknown'  
          };
          
          // Extract name if available
          if (practitionerData.name && practitionerData.name.length > 0) {
            const name = practitionerData.name[0];
            const given = name.given ? name.given.join(' ') : '';
            const family = name.family || '';
            practitionerInfo.name = `${given} ${family}`.trim() || 'Unknown';
          }
          
          // Extract contact info if available
          if (practitionerData.telecom && practitionerData.telecom.length > 0) {
            // Find email and phone
            practitionerData.telecom.forEach(contact => {
              if (contact.system === 'email' && contact.value) {
                practitionerInfo.email = contact.value;
              } else if (contact.system === 'phone' && contact.value) {
                practitionerInfo.phone = contact.value;
              }
            });
          }
          
          // Extract specialty from qualifications if available
          if (practitionerData.qualification && practitionerData.qualification.length > 0) {
            const qualification = practitionerData.qualification[0];
            if (qualification.code && qualification.code.text) {
              practitionerInfo.specialty = qualification.code.text;
            }
          }
          
          // Attach the formatted data to the practitioner object
          practitionerData._formatted = practitionerInfo;
          
          // Extract any qualifications/specialties if available
          if (practitionerData.qualification && practitionerData.qualification.length > 0) {
            const qualifications = practitionerData.qualification
              .map(q => q.code?.text || q.code?.coding?.[0]?.display)
              .filter(Boolean);
              
            if (qualifications.length > 0) {
              practitionerInfo.specialty = qualifications.join(', ');
            }
          }
          
          // Add formatted practitioner info to be used in template
          practitionerData._formatted = practitionerInfo;
        }
        
        // If fhirUser claim is present, fetch that resource too
        // Extract context information from token response
        console.log('Extracting context data');
        
        // Create an object to store all context data
        fhirUserData = { 
          context: {
            user: {},
            system: {},
            launch: {}
          }
        };
        
        // Extract any context from the token response
        Object.keys(tokenData).forEach(key => {
          // Skip standard OAuth fields
          if (!['access_token', 'token_type', 'expires_in', 'scope'].includes(key)) {
            fhirUserData.context.user[key] = tokenData[key];
          }
        });
        
        // Try to get system context information
        try {
          console.log('Fetching SMART configuration');
          const smartConfigResponse = await axios.get(`${SMART_SERVER_BASE}/.well-known/smart-configuration`);
          fhirUserData.context.system.smartConfiguration = smartConfigResponse.data;
        } catch (error) {
          console.log(`Error fetching SMART configuration: ${error.message}`);
        }
        
        // Try to access userinfo endpoint if available
        if (fhirUserData.context.system.smartConfiguration?.userinfo_endpoint) {
          try {
            console.log('Fetching user info');
            const userInfoResponse = await axios.get(
              fhirUserData.context.system.smartConfiguration.userinfo_endpoint,
              {
                headers: {
                  'Authorization': `Bearer ${tokenData.access_token}`,
                  'Accept': 'application/json'
                }
              }
            );
            fhirUserData.context.user.userInfo = userInfoResponse.data;
          } catch (error) {
            console.log(`Error fetching user info: ${error.message}`);
          }
        }
        
        // Add launch parameters if they exist
        if (req.session.launchContext) {
          fhirUserData.context.launch = req.session.launchContext;
        }
      } catch (dataError) {
        console.error('Error fetching practitioner data:', dataError);
        console.error('Error details:', dataError.response?.data || dataError.message);
      }
    }
    
    // Render the callback template with the results
    res.render('callback', {
      error: null,
      tokenResponse: tokenData,
      practitionerData,
      practitionerRoles,
      organizations,
      fhirUserData
    });
  } catch (error) {
    console.error('Error in callback:', error);
    res.render('callback', {
      error: error.message,
      tokenResponse: null,
      practitionerData: null,
      practitionerRoles: [],
      organizations: [],
      fhirUserData: null
    });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`SMART on FHIR client running at http://localhost:${PORT}`);
  console.log(`Redirect URI: ${REDIRECT_URI}`);
});
