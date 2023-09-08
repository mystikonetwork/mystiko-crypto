import { toBN, toBuff } from '@mystikonetwork/utils';
import { DecryptOutput } from '../../interface';
import { decryptNotes as decryptNotesImpl } from './impl';

export function decryptNotes(
  commitments: { commitmentHash: string; encryptedNote: string }[],
  keys: { publicKey: string; secretKey: string }[],
): Promise<DecryptOutput[]> {
  return decryptNotesImpl(
    commitments.map(({ commitmentHash, encryptedNote }) => ({
      commitmentHash: toBN(commitmentHash),
      encryptedNote: toBuff(encryptedNote),
    })),
    keys.map(({ publicKey, secretKey }) => ({ publicKey: toBuff(publicKey), secretKey: toBuff(secretKey) })),
  );
}
