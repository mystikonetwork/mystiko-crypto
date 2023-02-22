import { ProveOptions, VerifyOptions, ZKProof, ZKProver, ZKProverFactory } from '@mystikonetwork/zkp';
import { NopProver } from './nop';

export class NopProverFactory implements ZKProverFactory {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars,class-methods-use-this
  public create(options?: any): Promise<ZKProver<ZKProof, ProveOptions, VerifyOptions<ZKProof>>> {
    return Promise.resolve(new NopProver());
  }
}
