import { ZKProverFactory } from '@mystikonetwork/zkp';
import { ZokratesCliProver, ZokratesCliProverOptions } from './zokrates';

export class ZokratesCliProverFactory implements ZKProverFactory<ZokratesCliProverOptions> {
  // eslint-disable-next-line class-methods-use-this
  public create(options?: ZokratesCliProverOptions): Promise<ZokratesCliProver> {
    return Promise.resolve(new ZokratesCliProver(options));
  }
}
