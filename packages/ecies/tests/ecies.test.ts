import { FIELD_SIZE, toBN } from '@mystikonetwork/utils';
import { ECIES } from '../src';

test('test secret key/public key', () => {
  const sk = toBN('17271648533819761767633660408073145085934772589775836550317652488597130541763');
  const pk = ECIES.publicKey(sk);
  const unpackedPk = ECIES.unpackPublicKey(pk);
  expect(pk.toString()).toBe('72444700469954344414033902054315551824029723235242170438854670892932808883061');
  expect(unpackedPk.x.toString()).toBe(
    '17698851190026478217268086792453479467089177242109235834022425894878167006166',
  );
  expect(unpackedPk.y.toString()).toBe(
    '14548655851296246702248409549971597897394730902421888419125878888976244063093',
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
