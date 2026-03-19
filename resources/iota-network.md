IOTA network - its a blockchain network that has been forked from SUI. It supports move smart contracts

Documentation:  https://docs.iota.org/
Source code of IOTA: https://github.com/iotaledger/iota. This repo also includes the crates that would be useful to interact with the IOTA network


IOTA uses move language to build smart contracts:

the patterns:
The move in IOTA is mostly compatible with the one from SUI, so almost there is a useful move book:
https://move-book.com/
Its important to know about the Object model https://move-book.com/object/ and subsections and using objects https://move-book.com/storage/ with subsections (especially abilities)


On the top of IOTA there is a set of packages written in move that defines the trust framework.

Trust framework is made of the following components:

IOTA Trust framework - The components build on the top of IOTA network to support the application builders.  They exists in form of smart contracts (packages) built in move language. They are shipped with the rust lib and wasm bindings for TS
 Hierarchies  - https://github.com/iotaledger/hierarchies, additional documentation:https://docs.iota.org/developer/iota-hierarchies/explanations/about-hierarchies
 Identity - https://github.com/iotaledger/identity additional documentation: https://docs.iota.org/developer/iota-identity/explanations/decentralized-identifiers/
 Notarization  - https://github.com/iotaledger/notarization addtional documenattion: https://docs.iota.org/developer/iota-notarization/explanations/about-notarization


https://github.com/iotaledger/product-core/tree/feat/tf-compoenents-dev-revoked-caps/components_move
