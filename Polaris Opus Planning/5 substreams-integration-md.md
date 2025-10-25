# Substreams Integration - Real-time Blockchain Indexing

## Overview
Substreams provides real-time blockchain data indexing. This implementation captures anchored events, votes, stakes, and Respect updates from the chain.

## Substreams Configuration

```yaml
# File: substreams/substreams.yaml
# Manifest for Polaris music data indexing with Groups support

specVersion: v0.1.0
package:
  name: polaris_music
  version: v1.0.0
  url: https://github.com/polaris/music-substreams
  doc: Indexes Polaris music registry events including Groups

imports:
  entity: https://github.com/streamingfast/substreams-entity-change/releases/download/v0.2.1/substreams-entity-change-v0.2.1.spkg

binaries:
  default:
    type: wasm/rust-v1
    file: ./target/wasm32-unknown-unknown/release/polaris_music.wasm

modules:
  # ============ STORE MODULES ============
  # These maintain state across blocks
  
  # Store all anchored events
  - name: store_anchors
    kind: store
    initialBlock: 295000000  # Adjust to your deployment block
    updatePolicy: set
    valueType: proto:polaris.Anchor
    inputs:
      - source: sf.antelope.type.v1.Block
      
  # Store vote records with Respect weights
  - name: store_votes
    kind: store
    updatePolicy: set
    valueType: proto:polaris.VoteRecord
    inputs:
      - source: sf.antelope.type.v1.Block
      - store: store_respect
      
  # Store Fractally Respect values
  - name: store_respect
    kind: store
    updatePolicy: set
    valueType: proto:polaris.Respect
    inputs:
      - source: sf.antelope.type.v1.Block
      
  # Store stake aggregates by node
  - name: store_stakes
    kind: store
    updatePolicy: add  # Stakes accumulate
    valueType: proto:polaris.StakeAggregate
    inputs:
      - source: sf.antelope.type.v1.Block
      
  # Store group membership data
  - name: store_groups
    kind: store
    updatePolicy: set
    valueType: proto:polaris.GroupData
    inputs:
      - source: sf.antelope.type.v1.Block
      - map: map_anchor_events
      
  # ============ MAP MODULES ============
  # These transform blockchain data
  
  # Extract Polaris contract actions
  - name: map_polaris_actions
    kind: map
    inputs:
      - source: sf.antelope.type.v1.Block
    output:
      type: proto:polaris.Actions
      
  # Map anchor events for processing
  - name: map_anchor_events
    kind: map
    inputs:
      - source: sf.antelope.type.v1.Block
      - store: store_anchors
    output:
      type: proto:polaris.AnchorEvents
      
  # Map group-related events
  - name: map_group_events
    kind: map
    inputs:
      - source: sf.antelope.type.v1.Block
      - store: store_anchors
      - store: store_groups
    output:
      type: proto:polaris.GroupEvents
      
  # Map finalization events for rewards
  - name: map_finalizations
    kind: map
    inputs:
      - source: sf.antelope.type.v1.Block
      - store: store_anchors
      - store: store_votes
      - store: store_stakes
    output:
      type: proto:polaris.Finalizations
      
  # ============ SINK MODULE ============
  
  # Send to graph database
  - name: graph_out
    kind: map
    inputs:
      - map: map_anchor_events
      - map: map_group_events
      - map: map_finalizations
    output:
      type: proto:substreams.entity.v1.EntityChanges

protobuf:
  files:
    - polaris.proto
  importPaths:
    - ./proto
```

## Rust Implementation

```rust
// File: substreams/src/lib.rs
// Rust implementation of Substreams modules for Polaris with Groups

use substreams::prelude::*;
use substreams::store::{StoreGet, StoreGetProto, StoreSet, StoreSetProto};
use substreams_antelope::{Block, Action};
use substreams_entity_change::tables::Tables;
use hex;
use sha2::{Sha256, Digest};

// Import generated protobuf types
mod pb;
use pb::polaris;

/// Store all anchored events from the blockchain
/// This captures every event submission for processing
#[substreams::handlers::store]
fn store_anchors(block: Block, store: StoreSetProto<polaris::Anchor>) {
    for transaction in block.transactions() {
        // Skip failed transactions
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            // Filter for Polaris contract actions
            if trace.receiver != "polaris" {
                continue;
            }
            
            match trace.action_name.as_str() {
                "put" => {
                    // Extract anchor data from action
                    let data = decode_put_action(&trace.action);
                    
                    let anchor = polaris::Anchor {
                        id: generate_anchor_id(&data.hash),
                        author: data.author.to_string(),
                        event_type: data.event_type as i32,
                        hash: hex::encode(&data.hash),
                        parent: data.parent.map(|p| hex::encode(&p)),
                        timestamp: data.ts,
                        tags: data.tags.iter().map(|t| t.to_string()).collect(),
                        block_num: block.number,
                        transaction_id: hex::encode(&transaction.id),
                        finalized: false,
                        expires_at: data.ts + get_vote_window(data.event_type),
                    };
                    
                    // Store by hash for easy lookup
                    store.set(
                        anchor.id,
                        &format!("anchor:{}", anchor.hash),
                        &anchor,
                    );
                    
                    // Also store by type for filtering
                    store.set(
                        anchor.id,
                        &format!("type:{}:{}", anchor.event_type, anchor.hash),
                        &anchor,
                    );
                    
                    // Store by author for user queries
                    store.set(
                        anchor.id,
                        &format!("author:{}:{}", anchor.author, anchor.hash),
                        &anchor,
                    );
                    
                    log::info!("Stored anchor: {} type={} from {}", 
                              anchor.hash, anchor.event_type, anchor.author);
                }
                _ => {}
            }
        }
    }
}

/// Store vote records with Fractally Respect weights
/// Votes determine if submissions are accepted
#[substreams::handlers::store]
fn store_votes(
    block: Block, 
    respect_store: StoreGetProto<polaris::Respect>,
    store: StoreSetProto<polaris::VoteRecord>
) {
    for transaction in block.transactions() {
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            if trace.receiver != "polaris" || trace.action_name != "vote" {
                continue;
            }
            
            let data = decode_vote_action(&trace.action);
            
            // Look up voter's Respect for weight calculation
            let respect_key = format!("respect:{}", data.voter);
            let respect = respect_store
                .get_last(&respect_key)
                .map(|r| r.value)
                .unwrap_or(1); // Default Respect of 1
            
            let vote = polaris::VoteRecord {
                voter: data.voter.to_string(),
                tx_hash: hex::encode(&data.tx_hash),
                value: data.val as i32,
                weight: respect,
                timestamp: block.timestamp,
                block_num: block.number,
            };
            
            // Store vote by composite key (voter, hash)
            let key = format!("vote:{}:{}", vote.voter, vote.tx_hash);
            store.set(vote.voter.clone(), &key, &vote);
            
            log::info!("Stored vote: {} voted {} on {} with weight {}", 
                      vote.voter, vote.value, vote.tx_hash, vote.weight);
        }
    }
}

/// Store Fractally Respect values for vote weighting
/// Updated weekly from Fractally elections
#[substreams::handlers::store]
fn store_respect(block: Block, store: StoreSetProto<polaris::Respect>) {
    for transaction in block.transactions() {
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            if trace.receiver != "polaris" || trace.action_name != "updaterespect" {
                continue;
            }
            
            let data = decode_respect_update(&trace.action);
            
            for (account, respect_value) in data.respect_data {
                let respect = polaris::Respect {
                    account: account.to_string(),
                    value: respect_value,
                    round: data.election_round,
                    updated_at: block.timestamp,
                };
                
                let key = format!("respect:{}", account);
                store.set(account.clone(), &key, &respect);
                
                log::info!("Updated Respect: {} = {} (round {})", 
                          account, respect_value, data.election_round);
            }
        }
    }
}

/// Store stake aggregates for nodes (Groups, Persons, etc)
/// Stakes affect voting power and reward distribution
#[substreams::handlers::store]
fn store_stakes(block: Block, store: StoreSetProto<polaris::StakeAggregate>) {
    for transaction in block.transactions() {
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            if trace.receiver != "polaris" {
                continue;
            }
            
            match trace.action_name.as_str() {
                "stake" => {
                    let data = decode_stake_action(&trace.action);
                    let key = format!("stake:{}", hex::encode(&data.node_id));
                    
                    // Get current aggregate
                    let mut aggregate = store
                        .get_last(&key)
                        .unwrap_or_else(|| polaris::StakeAggregate {
                            node_id: hex::encode(&data.node_id),
                            total_amount: 0,
                            staker_count: 0,
                        });
                    
                    // Update totals
                    aggregate.total_amount += data.quantity.amount;
                    aggregate.staker_count += 1;
                    
                    store.set(0, &key, &aggregate);
                    
                    log::info!("Updated stake on {}: total={} stakers={}", 
                              aggregate.node_id, aggregate.total_amount, aggregate.staker_count);
                }
                "unstake" => {
                    let data = decode_unstake_action(&trace.action);
                    let key = format!("stake:{}", hex::encode(&data.node_id));
                    
                    if let Some(mut aggregate) = store.get_last(&key) {
                        aggregate.total_amount = aggregate.total_amount.saturating_sub(data.quantity.amount);
                        if aggregate.total_amount == 0 {
                            aggregate.staker_count = aggregate.staker_count.saturating_sub(1);
                        }
                        
                        store.set(0, &key, &aggregate);
                    }
                }
                _ => {}
            }
        }
    }
}

/// Store group membership and statistics
/// Tracks Groups and their members over time
#[substreams::handlers::store]
fn store_groups(
    block: Block,
    anchor_events: polaris::AnchorEvents,
    store: StoreSetProto<polaris::GroupData>
) {
    // Process CREATE_GROUP and ADD_MEMBER events
    for event in &anchor_events.events {
        if let Some(anchor) = &event.anchor {
            match event.event_type.as_str() {
                "CREATE_GROUP" => {
                    // Parse group creation data
                    // In production, would fetch and parse off-chain event
                    let group_data = polaris::GroupData {
                        group_id: generate_group_id(&anchor.hash),
                        name: "Group Name".to_string(), // Would come from event body
                        formed_date: anchor.timestamp,
                        member_count: 0,
                        active_member_count: 0,
                        track_count: 0,
                        release_count: 0,
                        last_updated: block.timestamp,
                    };
                    
                    let key = format!("group:{}", group_data.group_id);
                    store.set(0, &key, &group_data);
                    
                    log::info!("Created group: {} ({})", group_data.name, group_data.group_id);
                }
                
                "ADD_MEMBER" => {
                    // Update member counts
                    // Would parse event to get group_id
                    let group_id = ""; // Extract from event
                    let key = format!("group:{}", group_id);
                    
                    if let Some(mut group_data) = store.get_last(&key) {
                        group_data.member_count += 1;
                        group_data.active_member_count += 1;
                        group_data.last_updated = block.timestamp;
                        
                        store.set(0, &key, &group_data);
                    }
                }
                
                "REMOVE_MEMBER" => {
                    // Update active member count
                    let group_id = ""; // Extract from event
                    let key = format!("group:{}", group_id);
                    
                    if let Some(mut group_data) = store.get_last(&key) {
                        group_data.active_member_count = 
                            group_data.active_member_count.saturating_sub(1);
                        group_data.last_updated = block.timestamp;
                        
                        store.set(0, &key, &group_data);
                    }
                }
                
                _ => {}
            }
        }
    }
}

/// Map anchor events for downstream processing
/// Prepares events for graph database updates
#[substreams::handlers::map]
fn map_anchor_events(
    block: Block,
    anchors: StoreGetProto<polaris::Anchor>,
) -> Result<polaris::AnchorEvents, Error> {
    let mut events = polaris::AnchorEvents::default();
    
    for transaction in block.transactions() {
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            if trace.receiver != "polaris" || trace.action_name != "put" {
                continue;
            }
            
            let data = decode_put_action(&trace.action);
            let anchor_key = format!("anchor:{}", hex::encode(&data.hash));
            
            if let Some(anchor) = anchors.get_last(&anchor_key) {
                // Determine event type for routing
                let event_type = match anchor.event_type {
                    21 => "CREATE_RELEASE_BUNDLE",
                    22 => "CREATE_GROUP",
                    23 => "ADD_MEMBER",
                    24 => "REMOVE_MEMBER",
                    30 => "ADD_CLAIM",
                    31 => "EDIT_CLAIM",
                    40 => "VOTE",
                    41 => "LIKE",
                    42 => "DISCUSS",
                    50 => "FINALIZE",
                    60 => "MERGE_NODE",
                    _ => "UNKNOWN",
                };
                
                events.events.push(polaris::AnchorEvent {
                    anchor: Some(anchor.clone()),
                    event_type: event_type.to_string(),
                    needs_processing: !anchor.finalized,
                });
            }
        }
    }
    
    Ok(events)
}

/// Map group-specific events
/// Extracts group creation, member changes, etc.
#[substreams::handlers::map]
fn map_group_events(
    block: Block,
    anchors: StoreGetProto<polaris::Anchor>,
    groups: StoreGetProto<polaris::GroupData>,
) -> Result<polaris::GroupEvents, Error> {
    let mut events = polaris::GroupEvents::default();
    
    // Find all group-related anchors in this block
    for transaction in block.transactions() {
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            if trace.receiver != "polaris" || trace.action_name != "put" {
                continue;
            }
            
            let data = decode_put_action(&trace.action);
            
            // Check if this is a group-related event type
            if data.event_type == 22 || data.event_type == 23 || data.event_type == 24 {
                let anchor_key = format!("anchor:{}", hex::encode(&data.hash));
                
                if let Some(anchor) = anchors.get_last(&anchor_key) {
                    events.events.push(polaris::GroupEvent {
                        anchor: Some(anchor),
                        group_data: None, // Would fetch from store
                        event_type: get_event_type_name(data.event_type),
                        block_num: block.number,
                    });
                }
            }
        }
    }
    
    Ok(events)
}

/// Map finalization events for reward calculation
/// Processes voting outcomes and calculates emissions
#[substreams::handlers::map]
fn map_finalizations(
    block: Block,
    anchors: StoreGetProto<polaris::Anchor>,
    votes: StoreGetProto<polaris::VoteRecord>,
    stakes: StoreGetProto<polaris::StakeAggregate>,
) -> Result<polaris::Finalizations, Error> {
    let mut finalizations = polaris::Finalizations::default();
    
    for transaction in block.transactions() {
        if !transaction.executed {
            continue;
        }
        
        for trace in transaction.traces() {
            if trace.receiver != "polaris" || trace.action_name != "finalize" {
                continue;
            }
            
            let data = decode_finalize_action(&trace.action);
            let anchor_key = format!("anchor:{}", hex::encode(&data.tx_hash));
            
            if let Some(anchor) = anchors.get_last(&anchor_key) {
                // Calculate vote totals with Respect weights
                let (up_votes, down_votes) = calculate_weighted_votes(
                    &hex::encode(&data.tx_hash),
                    &votes
                );
                
                let total_votes = up_votes + down_votes;
                let approval = if total_votes > 0 {
                    (up_votes as f64) / (total_votes as f64)
                } else {
                    0.0
                };
                
                // Calculate emission using logarithmic curve
                let multiplier = get_multiplier(anchor.event_type);
                let x = get_global_counter(); // Would read from chain state
                let emission = if x > 0 {
                    (multiplier as f64) * (x as f64).ln() / (x as f64)
                } else {
                    0.0
                };
                
                finalizations.events.push(polaris::FinalizationEvent {
                    anchor_hash: anchor.hash.clone(),
                    approval_rating: approval,
                    outcome: if approval >= 0.9 { "ACCEPTED" } else { "REJECTED" }.to_string(),
                    emission_amount: emission,
                    up_votes,
                    down_votes,
                    total_votes,
                    block_num: block.number,
                });
                
                log::info!("Finalized {}: {} with {:.1}% approval, emission={:.2}", 
                          anchor.hash, 
                          if approval >= 0.9 { "ACCEPTED" } else { "REJECTED" },
                          approval * 100.0,
                          emission);
            }
        }
    }
    
    Ok(finalizations)
}

/// Convert Substreams data to Entity Changes for graph database
/// Final output that gets sent to the sink
#[substreams::handlers::map]
fn graph_out(
    anchor_events: polaris::AnchorEvents,
    group_events: polaris::GroupEvents,
    finalizations: polaris::Finalizations,
) -> Result<EntityChanges, Error> {
    let mut tables = Tables::new();
    
    // Process anchor events into graph operations
    for event in &anchor_events.events {
        if let Some(anchor) = &event.anchor {
            match event.event_type.as_str() {
                "CREATE_RELEASE_BUNDLE" => {
                    // Create entities for Release, Tracks, Songs, Groups
                    tables.create_row("releases", &anchor.hash)
                        .set("release_id", &anchor.hash)
                        .set("created_at", anchor.timestamp)
                        .set("author", &anchor.author);
                }
                
                "CREATE_GROUP" => {
                    tables.create_row("groups", &anchor.hash)
                        .set("group_id", &anchor.hash)
                        .set("created_at", anchor.timestamp)
                        .set("author", &anchor.author);
                }
                
                "ADD_MEMBER" => {
                    // Update Group membership
                    tables.create_row("memberships", &anchor.hash)
                        .set("member_id", "")  // Would extract from event
                        .set("group_id", "")   // Would extract from event
                        .set("from_date", anchor.timestamp);
                }
                
                _ => {}
            }
        }
    }
    
    // Process group events
    for event in &group_events.events {
        if let Some(anchor) = &event.anchor {
            tables.update_row("groups", &anchor.hash)
                .set("last_activity", event.block_num);
        }
    }
    
    // Process finalizations for reward distribution
    for finalization in &finalizations.events {
        tables.create_row("finalizations", &finalization.anchor_hash)
            .set("outcome", &finalization.outcome)
            .set("approval", finalization.approval_rating)
            .set("emission", finalization.emission_amount)
            .set("finalized_at", finalization.block_num);
    }
    
    Ok(tables.to_entity_changes())
}

// ============ HELPER FUNCTIONS ============

/// Calculate weighted vote totals using Respect
fn calculate_weighted_votes(
    tx_hash: &str,
    votes: &StoreGetProto<polaris::VoteRecord>
) -> (u64, u64) {
    let mut up_votes = 0u64;
    let mut down_votes = 0u64;
    
    // In production, would iterate through all votes for tx_hash
    // using prefix queries
    
    (up_votes, down_votes)
}

/// Get emission multiplier for event type
fn get_multiplier(event_type: i32) -> u64 {
    match event_type {
        21 => 1_000_000,  // CREATE_RELEASE_BUNDLE
        22 => 500_000,    // CREATE_GROUP
        23 => 100_000,    // ADD_MEMBER
        30 => 50_000,     // ADD_CLAIM
        31 => 1_000,      // EDIT_CLAIM
        _ => 0,
    }
}

/// Get voting window duration for event type
fn get_vote_window(event_type: u8) -> u32 {
    match event_type {
        21 | 22 => 7 * 24 * 60 * 60,  // 7 days for releases/groups
        30 | 31 => 3 * 24 * 60 * 60,  // 3 days for claims
        _ => 24 * 60 * 60,             // 1 day default
    }
}

/// Get event type name from code
fn get_event_type_name(event_type: u8) -> String {
    match event_type {
        21 => "CREATE_RELEASE_BUNDLE",
        22 => "CREATE_GROUP",
        23 => "ADD_MEMBER",
        24 => "REMOVE_MEMBER",
        30 => "ADD_CLAIM",
        31 => "EDIT_CLAIM",
        40 => "VOTE",
        41 => "LIKE",
        42 => "DISCUSS",
        50 => "FINALIZE",
        60 => "MERGE_NODE",
        _ => "UNKNOWN",
    }.to_string()
}

/// Get global submission counter
fn get_global_counter() -> u64 {
    // In production, read from chain state
    1000
}

/// Generate deterministic anchor ID from hash
fn generate_anchor_id(hash: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hash[0..8]);
    u64::from_le_bytes(bytes)
}

/// Generate group ID from hash
fn generate_group_id(hash: &str) -> String {
    format!("group:{}", &hash[0..16])
}

// ============ ACTION DECODERS ============
// These would decode the binary action data from the blockchain

struct PutAction {
    author: String,
    event_type: u8,
    hash: Vec<u8>,
    parent: Option<Vec<u8>>,
    ts: u32,
    tags: Vec<String>,
}

fn decode_put_action(action: &Action) -> PutAction {
    // Implementation would decode the action data
    PutAction {
        author: "".to_string(),
        event_type: 0,
        hash: vec![],
        parent: None,
        ts: 0,
        tags: vec![],
    }
}

struct VoteAction {
    voter: String,
    tx_hash: Vec<u8>,
    val: i8,
}

fn decode_vote_action(action: &Action) -> VoteAction {
    VoteAction {
        voter: "".to_string(),
        tx_hash: vec![],
        val: 0,
    }
}

// Additional decoder implementations...
```

## Protocol Buffer Definitions

```protobuf
// File: substreams/proto/polaris.proto
// Protocol buffer definitions for Polaris Substreams

syntax = "proto3";
package polaris;

// Anchored event record
message Anchor {
    uint64 id = 1;
    string author = 2;
    int32 event_type = 3;
    string hash = 4;
    optional string parent = 5;
    uint32 timestamp = 6;
    repeated string tags = 7;
    uint64 block_num = 8;
    string transaction_id = 9;
    bool finalized = 10;
    uint32 expires_at = 11;
}

// Vote record with Respect weight
message VoteRecord {
    string voter = 1;
    string tx_hash = 2;
    int32 value = 3;      // +1, 0, -1
    uint32 weight = 4;    // Respect value
    uint32 timestamp = 5;
    uint64 block_num = 6;
}

// Fractally Respect value
message Respect {
    string account = 1;
    uint32 value = 2;
    uint64 round = 3;
    uint32 updated_at = 4;
}

// Stake aggregate for a node
message StakeAggregate {
    string node_id = 1;
    uint64 total_amount = 2;
    uint32 staker_count = 3;
}

// Group data
message GroupData {
    string group_id = 1;
    string name = 2;
    uint32 formed_date = 3;
    uint32 member_count = 4;
    uint32 active_member_count = 5;
    uint32 track_count = 6;
    uint32 release_count = 7;
    uint32 last_updated = 8;
}

// Anchor event for processing
message AnchorEvent {
    Anchor anchor = 1;
    string event_type = 2;
    bool needs_processing = 3;
}

// Collection of anchor events
message AnchorEvents {
    repeated AnchorEvent events = 1;
}

// Group-specific event
message GroupEvent {
    Anchor anchor = 1;
    GroupData group_data = 2;
    string event_type = 3;
    uint64 block_num = 4;
}

// Collection of group events
message GroupEvents {
    repeated GroupEvent events = 1;
}

// Finalization event
message FinalizationEvent {
    string anchor_hash = 1;
    double approval_rating = 2;
    string outcome = 3;
    double emission_amount = 4;
    uint64 up_votes = 5;
    uint64 down_votes = 6;
    uint64 total_votes = 7;
    uint64 block_num = 8;
}

// Collection of finalizations
message Finalizations {
    repeated FinalizationEvent events = 1;
}
```

## Deployment

```bash
# Build the Substreams module
cargo build --target wasm32-unknown-unknown --release

# Test locally with Substreams CLI
substreams run -e eos.firehose.eosnation.io:9000 \
  substreams.yaml \
  map_anchor_events \
  --start-block 295000000 \
  --stop-block +100

# Deploy to production
substreams pack
substreams push substreams.spkg

# Set up sink to database
substreams sink postgres \
  -e eos.firehose.eosnation.io:9000 \
  substreams.yaml \
  --postgres-url postgresql://user:pass@localhost:5432/polaris \
  graph_out
```

## Monitoring

```rust
// Monitoring endpoints for Substreams health

/// Check if Substreams is processing blocks
fn health_check() -> bool {
    // Check latest processed block
    // Compare with chain head
    // Alert if lag > threshold
    true
}

/// Get processing statistics
fn get_stats() -> Stats {
    Stats {
        blocks_processed: 0,
        events_processed: 0,
        groups_created: 0,
        members_added: 0,
        votes_cast: 0,
        finalizations: 0,
    }
}
```