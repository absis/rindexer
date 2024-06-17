# rindexer

inspiration - https://ponder.sh/docs/guides/add-contracts

networks - https://github.com/ponder-sh/ponder/blob/83e2b4a7a05d847832ba60adde361736deeb3b2c/packages/core/src/config/networks.ts#L22

eth_getLogs - https://github.com/ponder-sh/ponder/blob/83e2b4a7a05d847832ba60adde361736deeb3b2c/packages/core/src/sync-historical/service.ts#L946

checklist v1.0:
- handle concurrency issues indexing and rate limits for RPCs
- fix TODOs
- look into making the rust handlers abstracted away a bit more with Arc and Box 
- look into .clone() to see if we can share some data
- go through all methods add summaries + refactor if needed
- finish the documentation
- look into setting your own schema for the database using diesel
- add a getting started guide for rust / no-code
- look into deployments to make it easy to do
- unit tests for the project

bugs:
- not having startBlock or endBlock throws and error on manifest

nice to have:

- investigate indexing contracts that are deployed within an event onchain
  - register a manifest defining factory including address, event, parameter name, and ABI
  - when it emits the event of the factory start a new log polling for the new contract
  - emit the log through the same event register as the event defined in the manifest

future features:
- look into migrating to alloy from ethers
- investigate handle advanced top of head reorgs process
- cron registering for networks to fire
- multiple ABIs merged into one
- look into load balancing of RPCs
- other db support
- look into internal caching to make things faster
- look into dependency mappings to allow you to index based on trees structure
- POC with shadow events using foundry as you index
- merge subgraph to rindexer yaml
- merge foundry to rindexer yaml
