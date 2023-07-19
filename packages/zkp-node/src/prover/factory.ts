import { ZKProverFactory } from '@mystikonetwork/zkp';
import { initialize, ZoKratesProvider } from 'zokrates-js';
import { ZokratesNodeProver, ZokratesNodeProverOptions } from './zokrates';

export class ZokratesNodeProverFactory implements ZKProverFactory<ZokratesNodeProverOptions> {
  // eslint-disable-next-line class-methods-use-this
  public create(options?: ZokratesNodeProverOptions): Promise<ZokratesNodeProver> {
    return initialize().then(
      (zokratesProvider: ZoKratesProvider) =>
        new ZokratesNodeProver(
          zokratesProvider.withOptions({
            backend: 'bellman',
            scheme: 'g16',
            curve: 'bn128',
          }),
          options,
        ),
    );
  }
}
