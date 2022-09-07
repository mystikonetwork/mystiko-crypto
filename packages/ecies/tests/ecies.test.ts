import { toBN } from '@mystikonetwork/utils';
import { ECIES } from '../src';

test('test secret key/public key', () => {
  const sk = toBN('6653394197986049121374360682484777687085153755365159319914007593958096971366');
  const pk = ECIES.publicKey(sk);
  const unpackedPk = ECIES.unpackPublicKey(pk);
  expect(pk.toString()).toBe('54076255637382257347592018492939936661737837603026694521812985613489874914839');
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
  const message = toBN(1234);
  const encrypted = ECIES.encrypt(message, pk, commonSk);
  const decrypted = ECIES.decrypt(encrypted, sk, commonPk);
  expect(decrypted.toNumber()).toBe(message.toNumber());
});
