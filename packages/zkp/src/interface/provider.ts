import { ZKProof, ZKVerificationKey } from './proof';

export interface ZKProvider<C = Uint8Array, PK = Uint8Array, VK = ZKVerificationKey, P = ZKProof> {
  prove(circuit: C, provingKey: PK): Promise<P>;
  verify(verifyingKey: VK, proof: P): Promise<boolean>;
}
