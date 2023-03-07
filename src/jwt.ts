import crypto from 'crypto';

export const Base64 = {
  encode: (str: string) => Buffer.from(str).toString('base64url'),
  decode: (str: string) => Buffer.from(str, 'base64url').toString('ascii'),
  signature: (header: string, payload: string, secret: string) => {
    return crypto.createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
  },
};

const compare = (header: string, payload: string, secret: string, signature: string): boolean => {
  return Base64.signature(header, payload, secret) === signature;
};

export const JWT = {
  create: (payload: Record<string, any>, secret: string, expire: number) => {
    const header = {
      alg: 'HS256',
      typ: 'JWT',
    };

    if (expire) payload.exp = Math.floor(Date.now() / 1000) + expire;

    const headerString = JSON.stringify(header);
    const payloadString = JSON.stringify(payload);

    const headerEncode = Base64.encode(headerString);
    const payloadEncode = Base64.encode(payloadString);
    const signature = Base64.signature(headerEncode, payloadEncode, secret);

    return [headerEncode, payloadEncode, signature].join('.');
  },
  verify: (token: string, secret: string) => {
    const parts = token.split('.');

    if (parts.length !== 3) throw new Error(`Invalid Token: ${token}`);

    const [headerEncode, payloadEncode, signature] = parts;

    const payloadDecode = Base64.decode(payloadEncode);

    const payload = JSON.parse(payloadDecode);

    const signatureCheck = compare(headerEncode, payloadEncode, secret, signature);

    if (!signatureCheck) throw new Error('Failed to authenticate');

    if (!signatureCheck) return payloadEncode;

    return payload;
  },
};
