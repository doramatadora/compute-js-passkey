const {
  browserSupportsWebAuthn,
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthnAutofill
} = SimpleWebAuthnBrowser

const PASSKEY_SUPPORTED = document.getElementById('passkeySupported')
const PASSKEY_FORM = document.getElementById('passkeyForm')
const COMPAT_MESSAGE = document.getElementById('passkeyNotSupported')
const REGISTER_BUTTON = document.getElementById('register')
const AUTHENTICATE_BUTTON = document.getElementById('authenticate')
const USER_NAME = document.getElementById('name')

// Availability of `window.PublicKeyCredential` means WebAuthn is usable.
// `isUserVerifyingPlatformAuthenticatorAvailable` means the feature detection is usable.
if (
  window.PublicKeyCredential &&
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
) {
  // Check if user verifying platform authenticator is available.
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
    .then(result => {
      if (result) {
        // Display form to register or authenticate.
        PASSKEY_SUPPORTED.style.display = 'block'
        REGISTER_BUTTON.addEventListener('click', async e => {
          e.preventDefault()
          const userName = USER_NAME.value
          const regStartResp = await fetch(`/registration/start/${userName}`)
          const regOptions = await regStartResp.json()
          console.log({ regOptions })
          // Start WebAuthn registration.
          const attResp = await startRegistration(regOptions)
          console.log({ attResp })
          // Verify attestation response.
          const regResp = await fetch(
            `/registration/finish/${userName}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(attResp)
            }
          )
          //console.log({ regResp })
          // Display outcome.
          if (regResp.ok === true) {
            const { verified } = await regResp.json()
            if (verified) {
              return alert(`Success! Now try to authenticate...`)
            }
          }
          alert(`Registration failed`)
        })
        AUTHENTICATE_BUTTON.addEventListener('click', async e => {
          e.preventDefault()
          const userName = USER_NAME.value
          const authStartResp = await fetch(`/authentication/start/${userName}`)
          const authOpts = await authStartResp.json()
          console.log({ authOpts })
          // Start WebAuthn authentication.
          const assResp = await startAuthentication(authOpts)
          console.log({ assResp })
          // Submit response.
          const authResp = await fetch(
            `/authentication/finish/${userName}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(assResp)
            }
          )
          // Display outcome.
          if (authResp.ok === true) {
            const { verified } = await regResp.json()
            if (verified) {
              return alert(`Success! You're authenticated`)
            }
          } 
          alert(`Authentication failed`)
        })
      } else {
        throw new Error(
          `User verifying platform authenticator is not available.`
        )
      }
    })
    .catch(() => {
      // Display message that WebAuthn is not supported.
      COMPAT_MESSAGE.style.display = 'block'
    })
}
