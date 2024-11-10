// https://medium.com/@joshuawright_63564/setting-up-a-single-sign-on-sso-saml-test-environment-nx-express-js-and-passportjs-e08e0742c120

import express from 'express';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy, VerifyWithoutRequest } from '@node-saml/passport-saml';
import { readFileSync } from 'fs';

const samlStrategy = new Strategy({
  callbackUrl: 'http://localhost:4300/login/callback',
  entryPoint: 'http://localhost:8080/simplesaml/saml2/idp/SSOService.php',
  issuer: 'saml-poc',
  decryptionPvk: readFileSync(`./certs/key.pem`, 'utf8'),
  privateKey: readFileSync(`./certs/key.pem`, 'utf8'),
  cert: readFileSync(`./certs/idp.pem`, 'utf8'),
  logoutUrl: 'http://localhost:8080/simplesaml/saml2/idp/SingleLogoutService.php',
  logoutCallbackUrl: 'http://localhost:4300/logout/callback'
},
  ((profile, done) => done(null, profile)) as VerifyWithoutRequest,
  ((profile, done) => done(null, profile)) as VerifyWithoutRequest
);

passport.serializeUser(function (user, done) {
  // Here we can manipulate IdP response for user profile
  done(null, user);
});
passport.deserializeUser((user, done) => done(null, user));
passport.use('samlStrategy', samlStrategy);

const app = express();

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // Enable in production
    sameSite: 'strict'
  }
}));
app.use(passport.initialize({}));
app.use(passport.session()); // Persist session

const host = 'localhost';
const port = 4300;
app.listen(4300, 'localhost', () => console.log(`[ ready ] http://${host}:${port}`));

// Clients must access this endpoint
app.get('/login', passport.authenticate('samlStrategy'));

// IdP will redirect sucessfull logins to this endpoint
// Maybe allow requests only for IdP ip
app.post('/login/callback',
  passport.authenticate('samlStrategy'),
  (req, res) => res.redirect('/profile')
);

app.get('/profile', (req, res) => {
  const user = req.user as IdPResponse
  if (!user?.attributes || !user) {
    return res.redirect('/login')
  }

  res.send(`Welcome back <strong>${user.attributes.email}</strong> 🎉`)
});

// It should be a post
app.get('/logout', function (req, res) {
  samlStrategy.logout(req as any, (error, requestUrl) => {
    if (error) {
      return res.status(500).send('Could not generate logout request');
    }
    res.redirect(requestUrl); // Redirect to IdP for logout
  });
});

// IdP will redirect to this endpoint after logout
app.get('/logout/callback', (req, res) => {
  // Handle IdP logout response and clear session
  req.logout((err) => {
    if (err) return res.status(500).send('Error clearing session');
    req.session.destroy(() => {
      res.redirect('/login'); // Redirect to home page or custom logout success page
    });
  });
});

// IdP access this endpoint to understand our SP config
app.route('/metadata').get(function (req, res) {
  res.type('application/xml');
  res.status(200);
  res.send(
    samlStrategy.generateServiceProviderMetadata(
      readFileSync('./certs/cert.pem', 'utf8'),
      readFileSync('./certs/cert.pem', 'utf8')
    )
  );
});