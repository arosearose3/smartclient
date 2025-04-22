/**
 * Minimal SMART on FHIR Client
 * A simple Express server that demonstrates SMART App launch flow
 * to authenticate and retrieve a Practitioner resource
 */

import express from 'express';
import session from 'express-session';
import crypto from 'crypto';
import axios from 'axios';
import { URL } from 'url';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Get the directory name
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const PORT = 3005;
const CLIENT_ID = 'minclient_dolv';
const BASE_URL = process.env.BASE_URL || 'https://corisystem.org';
const BASE_PATH = process.env.BASE_PATH || '/onecred';
const SMART_SERVER_BASE = `${BASE_URL}${BASE_PATH}/smart`;
const FHIR_SERVER_BASE = `${BASE_URL}${BASE_PATH}/smart/fhir`;
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
const viewsDir = path.join(__dirname, 'views');
if (!fs.existsSync(viewsDir)) {
  fs.mkdirSync(viewsDir);
}

// Create simple EJS templates
const indexTemplate = `
<!DOCTYPE html>
<html>
<head>
  <title>Minimal SMART on FHIR Client</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; }
    .container { border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-top: 20px; }
    button { background: #4CAF50; color: white; border: none; padding: 10px 15px; border-radius: 4px; cursor: pointer; }
    h1, h2 { color: #333; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>Minimal SMART on FHIR Client</h1>
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
  <title>SMART on FHIR - Practitioner Data</title>
  <style>
    body { font-family: Arial, sans-serif; line-height: 1.6; max-width: 1000px; margin: 0 auto; padding: 20px; background: #f9f9f9; }
    .container { border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-top: 20px; background: white; }
    .success { color: #4CAF50; }
    .error { color: #f44336; }
    h1, h2, h3 { color: #333; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    a { color: #0066cc; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>SMART on FHIR - Practitioner Data</h1>
  
  <% if (error) { %>
    <div class="container">
      <h2 class="error">Error</h2>
      <p><%= error %></p>
    </div>
  <% } else { %>
    <div class="container">
      <h2 class="success">Authentication Successful</h2>
      <p>Successfully authenticated with the SMART server!</p>
      
      <h3>Practitioner Resource</h3>
      <pre><%= JSON.stringify(practitionerData, null, 2) %></pre>
      
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

// SMART App Launch route
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
    
    // Fetch .well-known/smart-configuration to discover endpoints
    console.log('Fetching SMART configuration...');
    const smartConfigResponse = await axios.get(`${SMART_SERVER_BASE}/.well-known/smart-configuration`);
    const smartConfig = smartConfigResponse.data;
    
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

// OAuth Callback route
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
    console.log('Token received successfully');
    
    // Use the token to fetch Practitioner data
    let practitionerData = null;
    
    if (tokenData.access_token) {
      try {
        // Extract the practitioner ID from the token response
        const practitionerId = tokenData.practitioner;
        
        if (practitionerId) {
          console.log(`Fetching Practitioner data for ID: ${practitionerId}`);
          
          // Fetch the practitioner resource
          const practitionerResponse = await axios.get(`${FHIR_SERVER_BASE}/Practitioner/${practitionerId}`, {
            headers: {
              'Authorization': `Bearer ${tokenData.access_token}`,
              'Accept': 'application/json'
            }
          });
          
          practitionerData = practitionerResponse.data;
          console.log('Successfully fetched practitioner data');
        }
      } catch (dataError) {
        console.error('Error fetching practitioner data:', dataError);
        console.error('Error details:', dataError.response?.data || dataError.message);
      }
    }
    
    // Render the callback template with just the practitioner data
    res.render('callback', {
      error: null,
      practitionerData
    });
  } catch (error) {
    console.error('Error in callback:', error);
    res.render('callback', {
      error: error.message,
      practitionerData: null
    });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Minimal SMART on FHIR client running at http://localhost:${PORT}`);
  console.log(`Redirect URI: ${REDIRECT_URI}`);
});