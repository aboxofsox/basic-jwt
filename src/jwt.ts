import crypto from 'crypto'


const Base64 = {
    encode: (str: string) => Buffer.from(str).toString('base64'),
    decode: (str: string) => Buffer.from(str, 'base64').toString('ascii'),
    signature: (header: string, payload: string, secret: string) => {
        return crypto
            .createHmac('sha256', secret)
            .update(`${header}.${payload}`)
            .digest('base64')
    },
}

const compare = (header: string, payload: string, secret: string, signature: string): boolean => {
    return Base64.signature(header, payload, secret) === signature
}

export const JWT = {
    create: (payload: Record<string, any>, secret: string, expire: number) => {
        const header = {
            alg: 'HS256',
            typ: 'JWT',
        }

        const headerString = JSON.stringify(header)
        const payloadString = JSON.stringify(payload)

        const headerEncode = Base64.encode(headerString)
        const payloadEncode = Base64.encode(payloadString)
        const signature = Base64.signature(headerEncode, payloadEncode, secret)

        if (expire !== 0) payload.exp = Math.floor(Date.now() / 1000) + expire

        return [headerEncode, payloadEncode, signature].join('.')
    },
    verify: (token: string, secret: string) => {
        const parts = token.split('.')

        if (parts.length !== 3) throw new Error(`Invalid Token: ${token}`)

        const [headerEncode, payloadEncode, signature] = parts

        const payloadDecode = Base64.decode(payloadEncode)

        const payload = JSON.parse(payloadDecode)

        const signatureCheck = compare(headerEncode, payloadEncode, secret, signature)

        if (!signatureCheck) throw new Error(`Failed to authenticate`)

        return payload
    },
}