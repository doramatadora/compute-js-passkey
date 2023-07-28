/// <reference types="@fastly/js-compute" />

import base64url from 'base64url'
import { v4 as uuidv4 } from 'uuid';
import { includeBytes } from 'fastly:experimental'
import { KVStore } from 'fastly:kv-store'
import { Router } from '@fastly/expressly'

import {
  // Registration
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // Authentication
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server'
import { isoUint8Array } from '@simplewebauthn/server/helpers'

// Static files.
const indexPage = includeBytes('./src/browser/index.html')
const authScript = includeBytes('./src/browser/auth.js')
const styleSheet = includeBytes('./src/browser/style.css')

const KV_STORE = 'passkey-users'

// ✨ WEBAUTHN RELYING PARTY STUFF ✨
const RP_NAME = 'Passkeys@Edge'
const RP_ID = 'passkeys.edgecompute.app'
const ORIGIN = `https://${RP_ID}`

const router = new Router()

router.use((req, res) => {
  if (!['HEAD', 'GET', 'PURGE', 'POST'].includes(req.method)) {
    res.headers.set('Allow', 'HEAD, GET, PURGE, POST')
    res.withStatus(405).send('This method is not allowed')
  }
})

// Static assets.
router.get('/style.css', (_, res) => {
  res.headers.set('Content-Type', 'text/css; charset=utf-8')
  res.send(styleSheet)
})
router.get('/auth.js', (_, res) => {
  res.headers.set('Content-Type', 'text/javascript; charset=utf-8')
  res.send(authScript)
})
router.get('/', (_, res) => res.send(indexPage))

// ✨ REGISTRATION ✨
// Generate registration options.
router.get('/registration/start/:userName', async (req, res) => {
  // Get user from KVStore if exists.
  const users = new KVStore(KV_STORE)
  const user = await users
    .get(req.params.userName)
    .then(entry => (entry ? entry.json() : {
      id: uuidv4(),
      name: req.params.userName,
      devices: []
    }))

  const options = generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: user.id,
    userName: user.name,
    timeout: 60000,
    // Don't prompt users for additional information about the authenticator.
    attestationType: 'none',
    // Prevent users from re-registering existing authenticators.
    excludeCredentials: user.devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: dev.transports
    })),
    authenticatorSelection: {
      // "Discoverable credentials" used to be called "resident keys". The
      // old name persists in the options passed to `navigator.credentials.create()`.
      residentKey: 'required',
      userVerification: 'preferred'
    },
    supportedAlgorithmIDs: [-7, -257]
  })

  // Temporarily remember this value for verification.
  user.currentChallenge = options.challenge
  await users.put(user.name, JSON.stringify(user))

  res.json(options)
})

// Verify registration response.
router.post('/registration/finish/:userName', async (req, res) => {
  // The user needs to exist in KV Store at this point.
  const users = new KVStore(KV_STORE)
  const user = await users
    .get(req.params.userName)
    .then(entry => entry.json())

  const body = await req.json()
  console.log({body})

  const expectedChallenge = user.currentChallenge

  let verification
  try {
    verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true
    })
  } catch (e) {
    console.error(e)
    return res.withStatus(400).json({ error: e.message })
  }

  const { verified, registrationInfo } = verification

  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo

    const existingDevice = user.devices.find(device =>
      isoUint8Array.areEqual(device.credentialID, credentialID)
    )

    if (!existingDevice) {
      // Add the returned device to the user's list of devices.
      user.devices.push({
        credentialPublicKey,
        credentialID,
        counter,
        transports: body.response.transports
      })
    }
  }

  delete user.currentChallenge
  await users.put(user.name, JSON.stringify(user))

  res.json({ verified })
})

// ✨ AUTHENTICATION ✨
// Generate authentication options.
router.get('/authentication/start/:userName', async (req, res) => {
  // The user needs to exist in KV Store at this point.
  const users = new KVStore(KV_STORE)
  const user = await users
    .get(req.params.userName)
    .then(entry => entry.json())

  const options = generateAuthenticationOptions({
    timeout: 60000,
    allowCredentials: user.devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: dev.transports,
    })),
    userVerification: 'required',
    rpID: RP_ID,
  });

  // Temporarily remember this value for verification.
  user.currentChallenge = options.challenge
  await users.put(user.name, JSON.stringify(user))

  res.json(options);
});

// Verify authentication response.
router.post('/authentication/finish/:userName', async (req, res) => {
  // The user needs to exist in KV Store at this point.
  const users = new KVStore(KV_STORE)
  const user = await users
    .get(req.params.userName)
    .then(entry => entry.json())

  const body = await req.json()
  console.log({body})

  const expectedChallenge = user.currentChallenge


  const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
  // Find an authenticator matching the credential ID.
  const dbAuthenticator = user.devices.find((dev) => isoUint8Array.areEqual(dev.credentialID, bodyCredIDBuffer));

  if (!dbAuthenticator) {
    return res.withStatus(400).json({ error: 'Authenticator is not registered with this site' });
  }

  let verification
  try {
    verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: RP_ID,
      authenticator: dbAuthenticator,
      requireUserVerification: true,
    });
  } catch (e) {
    console.error(e)
    return res.withStatus(400).json({ error: e.message })
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator's counter. The parent (user) object will be updated in KV Store.
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  delete user.currentChallenge
  await users.put(user.name, JSON.stringify(user))

  res.json({ verified });
});

router.listen()
