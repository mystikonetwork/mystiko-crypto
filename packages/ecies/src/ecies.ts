import { FIELD_SIZE, toBN, toHexNoPrefix } from '@mystikonetwork/utils';
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
    return toBN(babyjub.packPoint(pk), 'hex', 'le');
  }

  public static unpackPublicKey(publicKey: BN): { x: BN; y: BN } {
    const unpacked = babyjub.unpackPoint(publicKey.toBuffer('le', KEY_LEN));
    return { x: toBN(unpacked[0].toString()), y: toBN(unpacked[1].toString()) };
  }

  public static encrypt(plain: BN, pk: BN, commonSk: BN): BN {
    const unpackedPk = ECIES.unpackPublicKey(pk);
    const k = babyjub.mulPointEscalar(
      [babyjub.F.e(unpackedPk.x.toString()), babyjub.F.e(unpackedPk.y.toString())],
      commonSk.toString(),
    );
    return ECIES.mod(plain.add(toBN(poseidon(k).toString())));
  }

  public static decrypt(encrypted: BN, sk: BN, commonPk: BN): BN {
    const unpackedGeneratedPk = ECIES.unpackPublicKey(commonPk);
    const k = babyjub.mulPointEscalar(
      [babyjub.F.e(unpackedGeneratedPk.x.toString()), babyjub.F.e(unpackedGeneratedPk.y.toString())],
      sk.toString(),
    );
    return ECIES.mod(encrypted.sub(toBN(poseidon(k))));
  }

  private static mod(aNumber: BN): BN {
    if (aNumber.gten(0)) {
      return aNumber.mod(FIELD_SIZE);
    }
    let remain = aNumber.mod(FIELD_SIZE).abs();
    if (!remain.isZero()) {
      remain = FIELD_SIZE.sub(remain);
    }
    return remain;
  }
}
