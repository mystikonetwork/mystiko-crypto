import { FIELD_SIZE, toBN, toHex } from '@mystikonetwork/utils';
import { ECIES } from '../src';

test('test secret key/public key', () => {
  const sk = toBN('6653394197986049121374360682484777687085153755365159319914007593958096971366');
  const pk = ECIES.publicKey(sk);
  const unpackedPk = ECIES.unpackPublicKey(pk);
  expect(toHex(pk)).toBe('0x778e137829c9d7e2c60c6b650ea759c9a823c8a88b7b0734c48f2a3108a3ce17');
  expect(unpackedPk.x.toString()).toBe(
    '6475168065192867422305723429513217789134682778204070412258950526142122128968',
  );
  expect(unpackedPk.y.toString()).toBe(
    '10768291218271385416922282155783865957968584166558170520694789924274952179319',
  );
});

test('test encrypt', () => {
  const commonSk = ECIES.generateSecretKey();
  const commonPk = ECIES.publicKey(commonSk);
  const sk = ECIES.generateSecretKey();
  const pk = ECIES.publicKey(sk);
  const message = toBN(FIELD_SIZE.subn(10));
  const encrypted = ECIES.encrypt(message, pk, commonSk);
  const decrypted = ECIES.decrypt(encrypted, sk, commonPk);
  expect(decrypted.toString()).toBe(message.toString());
});
