import BN from 'bn.js';
import { DecryptOutput } from '../../interface';
import { decryptNotes as decryptNotesImpl } from './impl';

export function decryptNotes(
  commitments: { commitmentHash: BN; encryptedNote: Buffer }[],
  keys: { publicKey: Buffer; secretKey: Buffer }[],
): Promise<DecryptOutput[]> {
  return decryptNotesImpl(commitments, keys);
}
