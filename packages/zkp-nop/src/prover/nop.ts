import { ProveOptions, VerifyOptions, ZKProof, ZKProver } from '@mystikonetwork/zkp';

export class NopProver implements ZKProver {
  // eslint-disable-next-line class-methods-use-this,@typescript-eslint/no-unused-vars
  public prove(options: ProveOptions): Promise<ZKProof> {
    return Promise.reject(new Error('Not implemented'));
  }

  // eslint-disable-next-line class-methods-use-this,@typescript-eslint/no-unused-vars
  public verify(options: VerifyOptions<ZKProof>): Promise<boolean> {
    return Promise.resolve(false);
  }
}
