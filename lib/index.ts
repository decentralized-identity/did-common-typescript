export { default as DidKey } from './crypto/DidKey';
export { default as KeyUse } from './crypto/KeyUse';
export { default as KeyType } from './crypto/KeyType';
export { default as KeyExport } from './crypto/KeyExport';
export { default as IDidDocument } from './IDidDocument';
export { default as IDidDocumentPublicKey } from './IDidDocumentPublicKey';
export { default as IDidDocumentServiceDescriptor } from './IDidDocumentServiceDescriptor';
export { default as IDidResolver } from './IDidResolver';
export { default as IDidResolveResult } from './IDidResolveResult';
export { default as HttpResolver, HttpResolverOptions } from './resolvers/HttpResolver';

import TestResolver from './mocks/TestResolver';
export const unitTestExports = {
  TestResolver
};
