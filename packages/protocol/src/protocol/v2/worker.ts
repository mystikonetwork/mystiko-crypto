import { DecryptOutput } from '../../interface';
import { decryptNotes as decryptNotesImpl } from './impl';

export function decryptNotes(
  encryptedNotes: Buffer[],
  keys: { publicKey: Buffer; secretKey: Buffer }[],
): Promise<DecryptOutput[]> {
  return decryptNotesImpl(encryptedNotes, keys);
}
