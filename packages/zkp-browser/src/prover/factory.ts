import { ZKProverFactory } from '@mystikonetwork/zkp';
import { ZoKratesProvider } from 'zokrates-js';
import { ZokratesBrowserProver } from './zokrates';

export class ZokratesBrowserProverFactory implements ZKProverFactory {
  // eslint-disable-next-line class-methods-use-this
  public create(): Promise<ZokratesBrowserProver> {
    // eslint-disable-next-line global-require
    const { initialize } = require('zokrates-js');
    return initialize().then(
      (provider: ZoKratesProvider) =>
        new ZokratesBrowserProver(
          provider.withOptions({
            backend: 'bellman',
            scheme: 'g16',
            curve: 'bn128',
          }),
        ),
    );
  }
}
