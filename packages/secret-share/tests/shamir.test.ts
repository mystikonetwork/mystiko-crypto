import { SecretSharing } from '../src';

test('test secret sharing', () => {
  const secret = SecretSharing.random();
  const { shares, threshold } = SecretSharing.split(secret, 30, 17);
  const recoveredSecret = SecretSharing.recover(shares.sort(() => Math.random() - 0.5).slice(0, threshold));
  expect(recoveredSecret.toString()).toBe(secret.toString());
});
