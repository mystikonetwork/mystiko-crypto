import { ZKProverFactory } from '@mystikonetwork/zkp';
import { ZoKratesProvider } from 'zokrates-js';
import { ZokratesNodeProver, ZokratesNodeProverOptions } from './zokrates';

export class ZokratesNodeProverFactory implements ZKProverFactory<ZokratesNodeProverOptions> {
  // eslint-disable-next-line class-methods-use-this
  public create(options?: ZokratesNodeProverOptions): Promise<ZokratesNodeProver> {
    // eslint-disable-next-line global-require
    const { initialize } = require('zokrates-js/node');
    return initialize().then(
      (zokratesProvider: ZoKratesProvider) => new ZokratesNodeProver(zokratesProvider, options),
    );
  }
}
