import { FIELD_SIZE, toBN, toBuff, toFixedLenHexNoPrefix, toHexNoPrefix } from '@mystikonetwork/utils';
import BN from 'bn.js';
import { babyjub, poseidon } from 'circomlibjs';
import randomBytes from 'randombytes';

export const KEY_LEN = 32;

export class ECIES {
  public static generateSecretKey(): BN {
    return toBN(toHexNoPrefix(randomBytes(KEY_LEN)), 16).mod(FIELD_SIZE);
  }

  public static publicKey(secretKey: BN): BN {
    const pk = babyjub.mulPointEscalar(babyjub.Base8, secretKey.toString());
    return toBN(toHexNoPrefix(babyjub.packPoint(pk)), 16);
  }

  public static unpackPublicKey(publicKey: BN): { x: BN; y: BN } {
    const pkBuffer = toBuff(toFixedLenHexNoPrefix(publicKey, KEY_LEN));
    const unpacked = babyjub.unpackPoint(pkBuffer);
    return { x: toBN(unpacked[0].toString()), y: toBN(unpacked[1].toString()) };
  }

  public static encrypt(plain: BN, pk: BN, commonSk: BN): BN {
    const unpackedPk = ECIES.unpackPublicKey(pk);
    const k = babyjub.mulPointEscalar(
      [babyjub.F.e(unpackedPk.x.toString()), babyjub.F.e(unpackedPk.y.toString())],
      commonSk.toString(),
    );
    return plain.add(toBN(poseidon(k).toString()));
  }

  public static decrypt(encrypted: BN, sk: BN, commonPk: BN): BN {
    const unpackedGeneratedPk = ECIES.unpackPublicKey(commonPk);
    const k = babyjub.mulPointEscalar(
      [babyjub.F.e(unpackedGeneratedPk.x.toString()), babyjub.F.e(unpackedGeneratedPk.y.toString())],
      sk.toString(),
    );
    return encrypted.sub(toBN(poseidon(k)));
  }
}
