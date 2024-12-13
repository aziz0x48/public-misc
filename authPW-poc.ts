const encoder = () => new TextEncoder();
const NAMESPACE = 'identity.mozilla.com/picl/v1/';

// These functions implement the onepw protocol
// https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol

export function uint8ToHex(array: Uint8Array): hexstring {
  return array.reduce(
    (str, byte) => str + ('00' + byte.toString(16)).slice(-2),
    ''
  );
}

export async function getCredentials(email: string, password: string) {
  const passkey = await crypto.subtle.importKey(
    'raw',
    encoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const quickStretchedRaw = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder().encode(`${NAMESPACE}quickStretch:${email}`),
      iterations: 1000,
      hash: 'SHA-256',
    },
    passkey,
    256
  );
  const quickStretchedKey = await crypto.subtle.importKey(
    'raw',
    quickStretchedRaw,
    'HKDF',
    false,
    ['deriveBits']
  );
  const authPW = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: new Uint8Array(0),
      // The builtin ts type definition for HKDF was wrong
      // at the time this was written, hence the ignore
      // @ts-ignore
      info: encoder().encode(`${NAMESPACE}authPW`),
      hash: 'SHA-256',
    },
    quickStretchedKey,
    256
  );
  const unwrapBKey = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: new Uint8Array(0),
      // @ts-ignore
      info: encoder().encode(`${NAMESPACE}unwrapBkey`),
      hash: 'SHA-256',
    },
    quickStretchedKey,
    256
  );
  return {
    authPW: uint8ToHex(new Uint8Array(authPW)),
    unwrapBKey: uint8ToHex(new Uint8Array(unwrapBKey)),
  };
}

  let authpw = getCredentials("aziz0x48+victim@wearehackerone.com", "passPass1")
  authpw.then(function(result) {
   console.log(result) 
})
