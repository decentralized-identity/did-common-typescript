export { default as DidDocument } from './DidDocument';
export { default as IDidDocument } from './IDidDocument';
export { default as IDidDocumentPublicKey } from './IDidDocumentPublicKey';
export { default as IDidDocumentServiceDescriptor } from './IDidDocumentServiceDescriptor';
export { default as IDidResolver } from './IDidResolver';
export { default as IDidResolveResult } from './IDidResolveResult';

import TestResolver from './mocks/TestResolver';
export const unitTestExports = {
  TestResolver
};
