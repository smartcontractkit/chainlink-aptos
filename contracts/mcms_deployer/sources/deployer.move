/// This module enables package deployment to a resource account while:
/// - allowing a deployed module to own its account's SignerCapability,
/// - keeping track of the deployer address without named addresses,
/// - and supporting large packages.
///
/// With object code deployment (see 0x1::object_code_deployment), the ExtendRef is
/// saved by the framework and not accessible to the deployed module, and the deployed
/// module will have to persist its singleton global state in derived resource accounts
/// or object, which adds complexity to observability and monitoring. In addition, it
/// provides its own ownership model which needs to be managed to avoid unexpected publishes
/// and upgrades to the object.
///
/// With resource account deployment (see 0x1::resource_account), the deployed module
/// does not know who the deployer is and who to give exceptional permissions to, until
/// a seperate initialization  function is called, which cannot be done in an atomic
/// fashion. During that period, any caller could potentially initialize the module before
/// the deployer as there is no method to validate the caller.
module mcms_deployer::deployer {
  use std::account::{Self, SignerCapability};
  use std::code;
  use std::signer;
  use std::smart_table::{Self, SmartTable};
  use std::vector;

  struct DeployerState has key, store {
    pending_deployments: SmartTable<vector<u8>, PendingDeployment>,
  }

  struct PendingDeployment has store {
    metadata_serialized: vector<u8>,
    code: vector<vector<u8>>,
  }

  struct PendingClaim has key, store {
    deployer_address: address,
    signer_cap: SignerCapability,
  }

  public entry fun publish_package(
      deployer: &signer,
      seed: vector<u8>,
      metadata_serialized: vector<u8>,
      code: vector<vector<u8>>,
  ) acquires DeployerState {
    ensure_state(deployer);

    let state = borrow_state_mut(signer::address_of(deployer));

    let pending_deployment = PendingDeployment { metadata_serialized, code };
    smart_table::add(&mut state.pending_deployments, seed, pending_deployment);

    execute_deployment(deployer, state, seed);
  }

  public entry fun stage_code_chunk(
      deployer: &signer,
      seed: vector<u8>,
      metadata_chunk: vector<u8>,
      code_indices: vector<u16>,
      code_chunks: vector<vector<u8>>,
  ) acquires DeployerState {
    ensure_state(deployer);

    let state = borrow_state_mut(signer::address_of(deployer));

    stage_code_chunk_internal(state, seed, metadata_chunk, code_indices, code_chunks);
  }

  public entry fun stage_code_chunk_and_publish(
      deployer: &signer,
      seed: vector<u8>,
      metadata_chunk: vector<u8>,
      code_indices: vector<u16>,
      code_chunks: vector<vector<u8>>,
  ) acquires DeployerState {
    ensure_state(deployer);

    let state = borrow_state_mut(signer::address_of(deployer));

    stage_code_chunk_internal(state, seed, metadata_chunk, code_indices, code_chunks);

    execute_deployment(deployer, state, seed);
  }

  public fun claim_resource_account(caller: &signer): (address, SignerCapability) acquires PendingClaim {
    let caller_address = signer::address_of(caller);

    let PendingClaim { deployer_address, signer_cap } = move_from<PendingClaim>(caller_address);

    (deployer_address, signer_cap)
  }

  inline fun ensure_state(deployer: &signer) {
    if (!exists<DeployerState>(signer::address_of(deployer))) {
      move_to(deployer, DeployerState {
        pending_deployments: smart_table::new(),
      });
    }
  }

  inline fun borrow_state(deployer_address: address): &DeployerState {
    borrow_global<DeployerState>(deployer_address)
  }

  inline fun borrow_state_mut(deployer_address: address): &mut DeployerState {
    borrow_global_mut<DeployerState>(deployer_address)
  }

  inline fun stage_code_chunk_internal(
    state: &mut DeployerState,
    seed: vector<u8>,
    metadata_chunk: vector<u8>,
    code_indices: vector<u16>,
    code_chunks: vector<vector<u8>>,
  ) {
    if (!smart_table::contains(&state.pending_deployments, seed)) {
      let pending_deployment = PendingDeployment {
        metadata_serialized: vector[],
        code: vector[],
      };
      smart_table::add(&mut state.pending_deployments, seed, pending_deployment);
    };

    let pending_deployment = smart_table::borrow_mut(&mut state.pending_deployments, seed);
    vector::append(&mut pending_deployment.metadata_serialized, metadata_chunk);

    vector::zip_ref(&code_indices, &code_chunks, |code_index, code_chunk| {
      let code_index = *code_index as u64;
      while (vector::length(&pending_deployment.code) <= code_index) {
        vector::push_back(&mut pending_deployment.code, vector[]);
      };
      let module_code = vector::borrow_mut(&mut pending_deployment.code, code_index);
      vector::append(module_code, *code_chunk);
    });
  }

  inline fun execute_deployment(deployer: &signer, state: &mut DeployerState, seed: vector<u8>) {
    let PendingDeployment { metadata_serialized, code } = smart_table::remove(&mut state.pending_deployments, seed);

    let (resource_signer, resource_signer_cap) = account::create_resource_account(deployer, seed);
    move_to(&resource_signer, PendingClaim { deployer_address: signer::address_of(deployer), signer_cap: resource_signer_cap });

    code::publish_package_txn(&resource_signer, metadata_serialized, code);

    if (smart_table::length(&state.pending_deployments) == 0) {
      let DeployerState { pending_deployments } = move_from<DeployerState>(signer::address_of(deployer));
      smart_table::destroy_empty(pending_deployments);
    }
  }
}
