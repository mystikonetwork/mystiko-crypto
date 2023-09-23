import { toBN, toBuff, toHex } from '@mystikonetwork/utils';
import { DecryptStringOutput } from '../../interface';
import { decryptNotes as decryptNotesImpl } from './impl';

export function decryptNotes(
  commitments: { commitmentHash: string; encryptedNote: string }[],
  keys: { publicKey: string; secretKey: string }[],
): Promise<DecryptStringOutput[]> {
  return decryptNotesImpl(
    commitments.map(({ commitmentHash, encryptedNote }) => ({
      commitmentHash: toBN(commitmentHash),
      encryptedNote: toBuff(encryptedNote),
    })),
    keys.map(({ publicKey, secretKey }) => ({ publicKey: toBuff(publicKey), secretKey: toBuff(secretKey) })),
  ).then((outputs) =>
    outputs.map((output) => ({
      commitment: {
        encryptedNote: toHex(output.commitment.encryptedNote),
        shieldedAddress: output.commitment.shieldedAddress,
        commitmentHash: output.commitment.commitmentHash.toString(),
        amount: output.commitment.amount.toString(),
        randomP: output.commitment.randomP.toString(),
        randomR: output.commitment.randomR.toString(),
        randomS: output.commitment.randomS.toString(),
        k: output.commitment.k.toString(),
      },
      shieldedAddress: output.shieldedAddress,
      serialNumber: output.serialNumber.toString(),
    })),
  );
}
