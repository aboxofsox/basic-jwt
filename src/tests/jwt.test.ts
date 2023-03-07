import { JWT, Base64 } from '../jwt';

describe('Base64', () => {
  const tests = ['foobarbaz', 'foobar', 'barbaz', 'foo'];

  tests.forEach((t, i) => {
    const encoded = Base64.encode(t);
    const decoded = Base64.decode(encoded);

    test(`Base64 Encoding ${i + 1}`, () => expect(decoded).toBe(t));
  });
});

describe('JWT', () => {
  const payload = {
    name: 'john doe',
    email: 'john.doe@doeboi.com',
  };
  const secret = 'doeboi';
  const expire = 3600;
  const token = JWT.create(payload, secret, expire);
  const tokenSplit = token.split('.');

  test('JWT token segments', () => expect(tokenSplit.length).toBe(3));

  const decoded = JWT.verify(token, secret);
  test('JWT verify', () =>
    expect(decoded).toStrictEqual({
      name: 'john doe',
      email: 'john.doe@doeboi.com',
      exp: Math.floor(Date.now() / 1000) + expire,
    }));
});
