# Event Processor - Blockchain Indexer

## Overview
Processes anchored events from the blockchain and updates the graph database. Handles Groups as first-class entities with proper member vs. guest distinctions.

## Implementation

```javascript
// File: backend/src/indexer/eventProcessor.js
// Watches blockchain for anchored events and processes them into the graph
// Integrates with Substreams for real-time processing

import { Api, JsonRpc } from 'eosjs';
import EventStore from '../storage/eventStore.js';
import MusicGraphDatabase from '../graph/schema.js';
import { EventTypes } from '../storage/eventStore.js';
import { createHash } from 'crypto';

class EventProcessor {
    constructor(config) {
        /**
         * Initialize connections to blockchain, storage, and database
         */
        
        // Blockchain RPC connection (fallback if Substreams unavailable)
        this.rpc = new JsonRpc(config.rpcUrl);
        
        // Event storage handler
        this.eventStore = new EventStore(config.storage);
        
        // Graph database handler
        this.graphDb = new MusicGraphDatabase(config.neo4j);
        
        // Processing state
        this.lastProcessedBlock = config.startBlock || 0;
        this.processingQueue = new Map();  // For batch processing
        this.isProcessing = false;
        
        // Configuration
        this.batchSize = config.batchSize || 100;
        this.pollInterval = config.pollInterval || 500; // ms
    }
    
    /**
     * Start processing events from the blockchain
     * Main entry point for the indexer
     */
    async start() {
        console.log('Starting event processor...');
        
        // Initialize database schema
        await this.graphDb.initializeSchema();
        
        // Check storage health
        const health = await this.eventStore.healthCheck();
        if (!health.overall) {
            throw new Error('Storage systems not healthy:', health);
        }
        
        // Start processing loop
        this.isProcessing = true;
        
        // Main processing loop
        while (this.isProcessing) {
            try {
                await this.processNewBlocks();
                await this.processQueue();
                await new Promise(resolve => setTimeout(resolve, this.pollInterval));
                
            } catch (error) {
                console.error('Processing error:', error);
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }
    }
    
    /**
     * Process new blocks from the blockchain
     * Fetches blocks and extracts relevant actions
     */
    async processNewBlocks() {
        // Get current chain head
        const info = await this.rpc.get_info();
        const headBlock = info.head_block_num;
        
        // Process blocks in batches
        while (this.lastProcessedBlock < headBlock) {
            const endBlock = Math.min(
                this.lastProcessedBlock + this.batchSize,
                headBlock
            );
            
            console.log(`Processing blocks ${this.lastProcessedBlock + 1} to ${endBlock}`);
            
            // Fetch and process block range
            for (let blockNum = this.lastProcessedBlock + 1; blockNum <= endBlock; blockNum++) {
                await this.processBlock(blockNum);
                this.lastProcessedBlock = blockNum;
                
                // Save progress periodically
                if (blockNum % 100 === 0) {
                    await this.saveProgress();
                }
            }
        }
    }
    
    /**
     * Process all relevant actions in a single block
     * 
     * @param {number} blockNum - Block number to process
     */
    async processBlock(blockNum) {
        const block = await this.rpc.get_block(blockNum);
        
        // Extract all actions from the block
        for (const tx of block.transactions) {
            // Skip failed transactions
            if (tx.status !== 'executed') continue;
            
            // Process each action in the transaction
            const trx = tx.trx.transaction || tx.trx;
            for (const action of trx.actions) {
                // Filter for Polaris contract actions
                if (action.account === 'polaris') {
                    await this.processAction(action, tx.trx.id, blockNum);
                }
            }
        }
    }
    
    /**
     * Process a single blockchain action
     * Routes to appropriate handler based on action name
     * 
     * @param {object} action - Blockchain action
     * @param {string} txId - Transaction ID
     * @param {number} blockNum - Block number
     */
    async processAction(action, txId, blockNum) {
        switch (action.name) {
            case 'put':
                // New event anchored
                await this.handleAnchor(action.data, txId, blockNum);
                break;
                
            case 'vote':
                // Vote on an event
                await this.handleVote(action.data, txId, blockNum);
                break;
                
            case 'finalize':
                // Finalize voting and distribute rewards
                await this.handleFinalize(action.data, txId, blockNum);
                break;
                
            case 'stake':
                // Stake on a node
                await this.handleStake(action.data, txId, blockNum);
                break;
                
            case 'updaterespect':
                // Fractally Respect update
                await this.handleRespectUpdate(action.data, txId, blockNum);
                break;
        }
    }
    
    /**
     * Handle a new anchored event
     * Fetches off-chain content and processes into graph
     * 
     * @param {object} anchorData - Anchor action data
     * @param {string} txId - Transaction ID
     * @param {number} blockNum - Block number
     */
    async handleAnchor(anchorData, txId, blockNum) {
        const { author, type, hash, parent, ts, tags } = anchorData;
        
        console.log(`Processing anchor: ${hash} type=${type} from ${author}`);
        
        // Add to processing queue
        this.processingQueue.set(hash, {
            author,
            type,
            hash,
            parent,
            ts,
            tags,
            txId,
            blockNum,
            attempts: 0
        });
    }
    
    /**
     * Process queued events
     * Fetches off-chain content and updates graph database
     */
    async processQueue() {
        if (this.processingQueue.size === 0) return;
        
        // Process events in batches
        const batch = Array.from(this.processingQueue.values())
            .slice(0, 10);
        
        for (const item of batch) {
            try {
                await this.processEvent(item);
                this.processingQueue.delete(item.hash);
                
            } catch (error) {
                console.error(`Failed to process ${item.hash}:`, error);
                item.attempts++;
                
                // Retry later or move to dead letter queue
                if (item.attempts > 3) {
                    console.error(`Giving up on ${item.hash} after 3 attempts`);
                    this.processingQueue.delete(item.hash);
                    await this.recordFailedEvent(item, error);
                }
            }
        }
    }
    
    /**
     * Process a single anchored event
     * Main routing logic for different event types
     * 
     * @param {object} item - Queue item with anchor data
     */
    async processEvent(item) {
        const { author, type, hash, txId, blockNum } = item;
        
        // Retrieve the full event from off-chain storage
        const event = await this.eventStore.retrieveEvent(hash);
        
        // Verify the event signature
        if (!this.eventStore.verifyEventSignature(event)) {
            throw new Error('Invalid event signature');
        }
        
        // Route based on event type
        const typeName = this.getEventTypeName(type);
        console.log(`Processing ${typeName} event ${hash}`);
        
        switch (typeName) {
            case 'CREATE_RELEASE_BUNDLE':
                await this.processReleaseBundle(event, hash, author);
                break;
                
            case 'CREATE_GROUP':
                await this.processCreateGroup(event, hash, author);
                break;
                
            case 'ADD_MEMBER':
                await this.processAddMember(event, hash, author);
                break;
                
            case 'REMOVE_MEMBER':
                await this.processRemoveMember(event, hash, author);
                break;
                
            case 'ADD_CLAIM':
                await this.processAddClaim(event, hash, author);
                break;
                
            case 'EDIT_CLAIM':
                await this.processEditClaim(event, hash, author);
                break;
                
            case 'VOTE':
                await this.processVote(event, hash, author);
                break;
                
            case 'LIKE':
                await this.processLike(event, hash, author);
                break;
                
            case 'DISCUSS':
                await this.processDiscussion(event, hash, author);
                break;
                
            case 'FINALIZE':
                await this.processFinalize(event, hash, author);
                break;
                
            case 'MERGE_NODE':
                await this.processMergeNode(event, hash, author);
                break;
                
            default:
                console.warn(`Unknown event type: ${typeName}`);
        }
        
        // Mark event as processed
        await this.markProcessed(hash, txId, blockNum);
    }
    
    /**
     * Process CREATE_RELEASE_BUNDLE event
     * Creates release, groups, tracks, and all relationships
     * 
     * @param {object} event - Event data
     * @param {string} hash - Event hash
     * @param {string} author - Submitter account
     */
    async processReleaseBundle(event, hash, author) {
        const bundle = event.body;
        
        // Process through graph database
        const result = await this.graphDb.processReleaseBundle(
            hash, 
            bundle,
            author
        );
        
        // Schedule for voting/finalization
        await this.scheduleFinalization(hash, event.created_at);
        
        console.log(`Release ${result.releaseId} processed: `, result.stats);
    }
    
    /**
     * Process CREATE_GROUP event
     * Creates a new group with founding members
     * 
     * @param {object} event - Event data
     * @param {string} hash - Event hash
     * @param {string} author - Submitter account
     */
    async processCreateGroup(event, hash, author) {
        const { group, founding_members, origin_city } = event.body;
        
        const session = this.graphDb.driver.session();
        const tx = session.beginTransaction();
        
        try {
            // Generate group ID if not provided
            const groupId = group.group_id || 
                           this.generateProvisionalId('group', group, founding_members);
            
            // Create the Group node
            await tx.run(`
                MERGE (g:Group {group_id: $groupId})
                SET g.name = $name,
                    g.alt_names = $altNames,
                    g.bio = $bio,
                    g.formed_date = $formedDate,
                    g.genre = $genre,
                    g.created_by = $author,
                    g.created_at = datetime(),
                    g.event_hash = $eventHash
                
                // Link to origin city if provided
                WITH g
                WHERE $cityId IS NOT NULL
                MERGE (c:City {city_id: $cityId})
                ON CREATE SET c.name = $cityName,
                             c.lat = $lat,
                             c.lon = $lon
                MERGE (g)-[:ORIGIN]->(c)
                
                // Link to submitter account
                WITH g
                MERGE (a:Account {account_id: $author})
                MERGE (a)-[:SUBMITTED {event_hash: $eventHash}]->(g)
                
                RETURN g
            `, {
                groupId,
                name: group.name,
                altNames: group.alt_names || [],
                bio: group.bio,
                formedDate: group.formed_date,
                genre: group.genre,
                author,
                eventHash: hash,
                cityId: origin_city?.city_id,
                cityName: origin_city?.name,
                lat: origin_city?.lat,
                lon: origin_city?.lon
            });
            
            // Add founding members
            for (const member of founding_members || []) {
                const personId = member.person_id || 
                                this.generateProvisionalId('person', member);
                
                await tx.run(`
                    MERGE (p:Person {person_id: $personId})
                    ON CREATE SET p.name = $name,
                                 p.status = $status
                    
                    WITH p
                    MATCH (g:Group {group_id: $groupId})
                    
                    // Create MEMBER_OF relationship
                    MERGE (p)-[m:MEMBER_OF {claim_id: $claimId}]->(g)
                    SET m.role = $role,
                        m.primary_instrument = $instrument,
                        m.from_date = $fromDate,
                        m.founding_member = true
                    
                    RETURN p, m
                `, {
                    personId,
                    name: member.name,
                    status: member.person_id ? 'canonical' : 'provisional',
                    groupId,
                    role: member.role || 'member',
                    instrument: member.instrument,
                    fromDate: group.formed_date,
                    claimId: this.generateOpId(hash, founding_members.indexOf(member))
                });
            }
            
            // Update member count
            await this.updateGroupStatistics(tx, groupId);
            
            await tx.commit();
            
            console.log(`Created group ${groupId} with ${founding_members?.length || 0} founding members`);
            
        } catch (error) {
            await tx.rollback();
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Process ADD_MEMBER event
     * Adds a person to an existing group
     * 
     * @param {object} event - Event data
     * @param {string} hash - Event hash
     * @param {string} author - Submitter account
     */
    async processAddMember(event, hash, author) {
        const { group_id, person, membership_details } = event.body;
        
        const session = this.graphDb.driver.session();
        const tx = session.beginTransaction();
        
        try {
            // Verify group exists
            const groupCheck = await tx.run(`
                MATCH (g:Group {group_id: $groupId})
                RETURN g
            `, { groupId: group_id });
            
            if (groupCheck.records.length === 0) {
                throw new Error(`Group ${group_id} not found`);
            }
            
            const personId = person.person_id || 
                            this.generateProvisionalId('person', person);
            
            // Add member to group
            await tx.run(`
                MERGE (p:Person {person_id: $personId})
                ON CREATE SET p.name = $name,
                             p.bio = $bio,
                             p.status = $status
                
                WITH p
                MATCH (g:Group {group_id: $groupId})
                
                // Check if already a member
                OPTIONAL MATCH (p)-[existing:MEMBER_OF]->(g)
                
                // Only create if not already a member
                FOREACH (_ IN CASE WHEN existing IS NULL THEN [1] ELSE [] END |
                    CREATE (p)-[m:MEMBER_OF {
                        claim_id: $claimId,
                        role: $role,
                        primary_instrument: $instrument,
                        from_date: $fromDate,
                        to_date: $toDate,
                        added_by: $author,
                        added_at: datetime()
                    }]->(g)
                )
                
                RETURN p, g, existing IS NOT NULL as wasUpdate
            `, {
                personId,
                name: person.name,
                bio: person.bio,
                status: person.person_id ? 'canonical' : 'provisional',
                groupId: group_id,
                claimId: this.generateOpId(hash, 0),
                role: membership_details.role,
                instrument: membership_details.instrument,
                fromDate: membership_details.from_date,
                toDate: membership_details.to_date,
                author
            });
            
            // Update group statistics
            await this.updateGroupStatistics(tx, group_id);
            
            await tx.commit();
            
            console.log(`Added member ${personId} to group ${group_id}`);
            
        } catch (error) {
            await tx.rollback();
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Process REMOVE_MEMBER event
     * Marks a member as departed from a group
     * 
     * @param {object} event - Event data
     * @param {string} hash - Event hash
     * @param {string} author - Submitter account
     */
    async processRemoveMember(event, hash, author) {
        const { group_id, person_id, departure_date, reason } = event.body;
        
        const session = this.graphDb.driver.session();
        
        try {
            // Update membership end date
            await session.run(`
                MATCH (p:Person {person_id: $personId})
                MATCH (p)-[m:MEMBER_OF]->(g:Group {group_id: $groupId})
                WHERE m.to_date IS NULL
                SET m.to_date = $departureDate,
                    m.departure_reason = $reason,
                    m.updated_by = $author,
                    m.updated_at = datetime()
                RETURN p, g
            `, {
                personId: person_id,
                groupId: group_id,
                departureDate: departure_date,
                reason: reason || 'departed',
                author
            });
            
            console.log(`Removed member ${person_id} from group ${group_id}`);
            
        } finally {
            await session.close();
        }
    }
    
    /**
     * Process tracks distinguishing groups vs guests
     * Critical for proper attribution
     * 
     * @param {object} track - Track data
     * @param {string} trackId - Track identifier
     * @param {string} eventHash - Source event hash
     */
    async processTrackCredits(tx, track, trackId, eventHash) {
        let opIndex = 0;
        const getOpId = () => this.generateOpId(eventHash, opIndex++);
        
        // Process primary performing group
        if (track.performed_by_group) {
            await tx.run(`
                MATCH (t:Track {track_id: $trackId})
                MERGE (g:Group {group_id: $groupId})
                ON CREATE SET g.name = $groupName,
                             g.status = 'provisional'
                
                // PERFORMED_ON relationship for the group
                MERGE (g)-[p:PERFORMED_ON {claim_id: $claimId}]->(t)
                SET p.role = 'primary_artist',
                    p.credited_as = $creditedAs
            `, {
                trackId,
                groupId: track.performed_by_group.group_id,
                groupName: track.performed_by_group.name || 'Unknown Group',
                creditedAs: track.performed_by_group.credited_as,
                claimId: getOpId()
            });
        }
        
        // Process guest performers (non-group members)
        for (const guest of track.guests || []) {
            const guestId = guest.person_id || 
                           this.generateProvisionalId('person', guest);
            
            await tx.run(`
                MERGE (p:Person {person_id: $personId})
                ON CREATE SET p.name = $name,
                             p.status = $status
                
                WITH p
                MATCH (t:Track {track_id: $trackId})
                
                // GUEST_ON relationship for non-members
                MERGE (p)-[g:GUEST_ON {claim_id: $claimId}]->(t)
                SET g.role = $role,
                    g.instrument = $instrument,
                    g.credited_as = $creditedAs,
                    g.featuring = $featuring
            `, {
                personId: guestId,
                name: guest.name,
                status: guest.person_id ? 'canonical' : 'provisional',
                trackId,
                role: guest.role,
                instrument: guest.instrument,
                creditedAs: guest.credited_as,
                featuring: guest.featuring || false,
                claimId: getOpId()
            });
        }
    }
    
    /**
     * Update group statistics after membership changes
     * 
     * @param {Transaction} tx - Active database transaction
     * @param {string} groupId - Group to update
     */
    async updateGroupStatistics(tx, groupId) {
        await tx.run(`
            MATCH (g:Group {group_id: $groupId})
            
            // Count members
            OPTIONAL MATCH (p:Person)-[m:MEMBER_OF]->(g)
            WITH g, count(p) as totalMembers,
                 sum(CASE WHEN m.to_date IS NULL THEN 1 ELSE 0 END) as activeMembers
            
            // Count tracks and releases
            OPTIONAL MATCH (g)-[:PERFORMED_ON]->(t:Track)
            OPTIONAL MATCH (t)-[:IN_RELEASE]->(r:Release)
            
            WITH g, totalMembers, activeMembers,
                 count(DISTINCT t) as trackCount,
                 count(DISTINCT r) as releaseCount
            
            SET g.member_count = totalMembers,
                g.active_member_count = activeMembers,
                g.track_count = trackCount,
                g.release_count = releaseCount,
                g.updated_at = datetime()
            
            RETURN g
        `, { groupId });
    }
    
    /**
     * Schedule event for finalization after voting window
     * 
     * @param {string} eventHash - Event to finalize
     * @param {number} createdAt - Event creation timestamp
     */
    async scheduleFinalization(eventHash, createdAt) {
        const VOTE_WINDOW = 7 * 24 * 60 * 60; // 7 days
        const finalizeAt = createdAt + VOTE_WINDOW;
        const delayMs = (finalizeAt - Date.now() / 1000) * 1000;
        
        if (delayMs > 0) {
            // Schedule for future
            setTimeout(() => {
                this.finalizeEvent(eventHash);
            }, delayMs);
            
            console.log(`Scheduled finalization for ${eventHash} in ${delayMs / 1000} seconds`);
        } else {
            // Already past window, finalize now
            await this.finalizeEvent(eventHash);
        }
    }
    
    /**
     * Finalize event and calculate rewards
     * 
     * @param {string} eventHash - Event to finalize
     */
    async finalizeEvent(eventHash) {
        // This would call the smart contract finalize action
        // For now, log the finalization
        console.log(`Finalizing event ${eventHash}`);
        
        // TODO: Call blockchain finalize action
        // TODO: Process reward distribution
    }
    
    /**
     * Mark event as processed in tracking database
     * 
     * @param {string} hash - Event hash
     * @param {string} txId - Transaction ID
     * @param {number} blockNum - Block number
     */
    async markProcessed(hash, txId, blockNum) {
        // Store processing record
        // This could be in Redis or a tracking table
        await this.eventStore.redis.hset(
            'processed_events',
            hash,
            JSON.stringify({
                txId,
                blockNum,
                processedAt: new Date().toISOString()
            })
        );
    }
    
    /**
     * Save processing progress for recovery
     */
    async saveProgress() {
        await this.eventStore.redis.set(
            'processor:last_block',
            this.lastProcessedBlock
        );
    }
    
    /**
     * Generate provisional ID for entities without external IDs
     */
    generateProvisionalId(type, data, additionalData = []) {
        let normalizedString;
        
        switch(type) {
            case 'group':
                normalizedString = [
                    data.name?.toLowerCase(),
                    data.formed_date,
                    ...additionalData.map(m => m.name).sort()
                ].join('|');
                break;
                
            case 'person':
                normalizedString = data.name?.toLowerCase() || '';
                break;
                
            default:
                normalizedString = JSON.stringify(data);
        }
        
        const hash = createHash('sha256')
            .update(normalizedString)
            .digest('hex')
            .substring(0, 16);
            
        return `prov:${type}:${hash}`;
    }
    
    /**
     * Generate operation ID for sub-operations
     */
    generateOpId(eventHash, index) {
        return createHash('sha256')
            .update(eventHash + index.toString())
            .digest('hex');
    }
    
    /**
     * Get event type name from numeric code
     */
    getEventTypeName(type) {
        const types = {
            21: 'CREATE_RELEASE_BUNDLE',
            22: 'CREATE_GROUP',
            23: 'ADD_MEMBER',
            24: 'REMOVE_MEMBER',
            30: 'ADD_CLAIM',
            31: 'EDIT_CLAIM',
            40: 'VOTE',
            41: 'LIKE',
            42: 'DISCUSS',
            50: 'FINALIZE',
            60: 'MERGE_NODE'
        };
        return types[type] || 'UNKNOWN';
    }
    
    /**
     * Stop processing and clean up
     */
    async stop() {
        this.isProcessing = false;
        await this.saveProgress();
        await this.graphDb.close();
        await this.eventStore.close();
        console.log('Event processor stopped');
    }
}

export default EventProcessor;
```

## Processing Flow

```
┌─────────────────────────────────────────────┐
│            Blockchain Block                  │
│         (Contains Anchor Actions)            │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
          ┌──────────────┐
          │ Extract Hash │
          │  from Anchor │
          └──────┬───────┘
                 │
                 ▼
         ┌───────────────┐
         │ Fetch Event   │
         │ from Storage  │
         └──────┬────────┘
                │
                ▼
        ┌────────────────┐
        │ Verify Signature│
        │   and Hash     │
        └───────┬────────┘
                │
                ▼
        ┌───────────────┐
        │ Route by Type │
        └───────┬───────┘
                │
    ┌───────────┼───────────┬──────────┬──────────┐
    ▼           ▼           ▼          ▼          ▼
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│Release │ │ Group  │ │ Member │ │ Claim  │ │  Vote  │
│Bundle  │ │ Create │ │Add/Rem │ │Add/Edit│ │Process │
└───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘
    │          │          │          │          │
    └──────────┴──────────┴──────────┴──────────┘
                          │
                          ▼
                  ┌──────────────┐
                  │ Update Graph │
                  │   Database   │
                  └──────────────┘
```

## Testing

```javascript
// Test event processor
const processor = new EventProcessor({
    rpcUrl: 'https://eos.greymass.com',
    startBlock: 300000000,
    storage: {
        ipfsUrl: 'http://localhost:5001',
        aws: { /* config */ },
        redis: { /* config */ }
    },
    neo4j: {
        uri: 'bolt://localhost:7687',
        user: 'neo4j',
        password: 'password'
    }
});

// Start processing
processor.start();

// Test specific event processing
const testEvent = {
    type: 'CREATE_GROUP',
    body: {
        group: {
            name: 'Test Band',
            formed_date: '2024-01-01'
        },
        founding_members: [
            { name: 'Alice', role: 'vocalist' },
            { name: 'Bob', role: 'guitarist' }
        ]
    }
};

processor.processCreateGroup(testEvent, 'test-hash', 'testaccount');
```