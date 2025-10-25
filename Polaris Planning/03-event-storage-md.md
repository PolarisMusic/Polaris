# Event Storage - Off-chain Canonical Events

## Overview
Handles storage and retrieval of canonical off-chain events. Events are stored in multiple locations for redundancy and are content-addressed by SHA-256 hash.

## Implementation

```javascript
// File: backend/src/storage/eventStore.js
// Manages off-chain event storage across IPFS, S3, and local cache
// All events are canonical (deterministic) and signed

import { create } from 'ipfs-http-client';
import AWS from 'aws-sdk';
import { canonicalize } from 'json-canonicalize';
import { createHash, sign, verify } from 'crypto';
import { PrivateKey, PublicKey, Signature } from 'eosjs/dist/eosjs-key-conversions';
import Redis from 'ioredis';

class EventStore {
    constructor(config) {
        /**
         * Initialize storage backends
         * We use multiple storage layers for redundancy and performance
         */
        
        // IPFS for decentralized, content-addressed storage
        this.ipfs = create({ 
            url: config.ipfsUrl,
            timeout: 30000
        });
        
        // S3 for fast CDN-backed retrieval
        this.s3 = new AWS.S3({
            accessKeyId: config.aws.accessKeyId,
            secretAccessKey: config.aws.secretAccessKey,
            region: config.aws.region
        });
        this.bucket = config.aws.bucket;
        
        // Redis for hot cache
        this.redis = new Redis({
            host: config.redis.host,
            port: config.redis.port,
            password: config.redis.password,
            retryStrategy: (times) => Math.min(times * 50, 2000)
        });
        
        // Local file cache
        this.localCachePath = config.localCachePath || './cache/events';
        
        // Minimum number of successful stores before anchoring
        this.minRedundancy = config.minRedundancy || 2;
    }
    
    /**
     * Create a canonical event with deterministic structure
     * This ensures the same event always produces the same hash
     * Events follow the Clarion-style format
     * 
     * @param {string} type - Event type (CREATE_RELEASE_BUNDLE, CREATE_GROUP, etc)
     * @param {object} body - Event-specific payload
     * @param {string} authorPubkey - EOS public key of author
     * @param {array} parents - Optional parent event hashes for threading
     * @param {object} proofs - Optional external proofs/sources
     * @returns {object} Event object with hash
     */
    async createEvent(type, body, authorPubkey, parents = [], proofs = {}) {
        // Create the event structure
        const event = {
            v: 1,                           // Version for future compatibility
            type,                          // Event type string
            author_pubkey: authorPubkey,   // EOS public key
            created_at: Math.floor(Date.now() / 1000), // Unix timestamp
            parents,                       // Parent events for threading
            body,                          // Main payload
            proofs                         // External references
        };
        
        // Canonicalize to ensure deterministic JSON
        // This uses RFC 8785 JSON Canonicalization Scheme
        const canonical = canonicalize(event);
        
        // Calculate SHA-256 hash of canonical bytes
        const hashBuffer = createHash('sha256').update(canonical).digest();
        const hash = hashBuffer.toString('hex');
        
        // Event is not yet signed - that happens client-side
        // Return structure ready for signing
        return { 
            event, 
            canonical, 
            hash,
            hashBuffer
        };
    }
    
    /**
     * Sign an event with EOS private key
     * This proves the author created this exact event
     * 
     * @param {object} event - Event to sign
     * @param {string} privateKey - EOS private key
     * @returns {object} Signed event
     */
    signEvent(event, privateKey) {
        // Convert EOS private key to signing key
        const key = PrivateKey.fromString(privateKey);
        
        // Sign the hash
        const signature = key.sign(event.hashBuffer, false, 'utf8');
        
        // Add signature to event
        event.event.sig = signature.toString();
        
        return event;
    }
    
    /**
     * Verify an event signature
     * Ensures the event hasn't been tampered with
     * 
     * @param {object} event - Event with signature
     * @returns {boolean} True if valid
     */
    verifyEventSignature(event) {
        try {
            // Extract signature and remove from event for verification
            const { sig, ...eventWithoutSig } = event;
            
            // Recreate canonical form
            const canonical = canonicalize(eventWithoutSig);
            const hashBuffer = createHash('sha256').update(canonical).digest();
            
            // Convert public key and signature
            const pubKey = PublicKey.fromString(event.author_pubkey);
            const signature = Signature.fromString(sig);
            
            // Verify signature
            return signature.verify(hashBuffer, pubKey, false, 'utf8');
        } catch (error) {
            console.error('Signature verification failed:', error);
            return false;
        }
    }
    
    /**
     * Store event in multiple locations for redundancy
     * Must succeed in at least minRedundancy locations before anchoring
     * 
     * @param {object} event - Complete signed event
     * @param {string} hash - Event hash
     * @returns {array} Storage locations where successful
     */
    async storeEvent(event, hash) {
        const stored = [];
        const errors = [];
        
        // Prepare event data
        const eventJson = JSON.stringify(event);
        const eventBuffer = Buffer.from(eventJson);
        
        // === 1. Store in Redis (hot cache) ===
        try {
            await this.redis.set(
                `event:${hash}`, 
                eventJson,
                'EX', 86400 * 7  // Expire after 7 days
            );
            stored.push({ type: 'redis', key: hash });
        } catch (error) {
            console.error('Redis storage failed:', error);
            errors.push({ type: 'redis', error: error.message });
        }
        
        // === 2. Store in IPFS (decentralized) ===
        try {
            const ipfsResult = await this.ipfs.add({
                path: `${hash}.json`,
                content: eventBuffer
            }, {
                pin: true,  // Pin to prevent garbage collection
                timeout: 10000
            });
            
            stored.push({ 
                type: 'ipfs', 
                cid: ipfsResult.cid.toString(),
                path: ipfsResult.path
            });
            
            // Also pin by hash for easier retrieval
            await this.ipfs.pin.add(ipfsResult.cid);
            
        } catch (error) {
            console.error('IPFS storage failed:', error);
            errors.push({ type: 'ipfs', error: error.message });
        }
        
        // === 3. Store in S3 (CDN-backed) ===
        try {
            await this.s3.putObject({
                Bucket: this.bucket,
                Key: `events/${hash}.json`,
                Body: eventBuffer,
                ContentType: 'application/json',
                // Immutable content - can cache forever
                CacheControl: 'public, max-age=31536000, immutable',
                Metadata: {
                    'event-type': event.type,
                    'event-author': event.author_pubkey,
                    'event-timestamp': event.created_at.toString()
                }
            }).promise();
            
            stored.push({ 
                type: 's3', 
                bucket: this.bucket,
                key: `events/${hash}.json` 
            });
            
        } catch (error) {
            console.error('S3 storage failed:', error);
            errors.push({ type: 's3', error: error.message });
        }
        
        // === 4. Store locally (fallback) ===
        try {
            const fs = require('fs').promises;
            const path = require('path');
            
            const filePath = path.join(this.localCachePath, `${hash}.json`);
            await fs.mkdir(path.dirname(filePath), { recursive: true });
            await fs.writeFile(filePath, eventJson);
            
            stored.push({ 
                type: 'local', 
                path: filePath 
            });
            
        } catch (error) {
            console.error('Local storage failed:', error);
            errors.push({ type: 'local', error: error.message });
        }
        
        // Check minimum redundancy requirement
        if (stored.length < this.minRedundancy) {
            throw new Error(
                `Failed to achieve minimum redundancy. ` +
                `Required: ${this.minRedundancy}, Successful: ${stored.length}. ` +
                `Errors: ${JSON.stringify(errors)}`
            );
        }
        
        // Log storage summary
        console.log(`Event ${hash} stored in ${stored.length} locations:`, 
                   stored.map(s => s.type).join(', '));
        
        return stored;
    }
    
    /**
     * Retrieve event from any available source
     * Tries fastest sources first, falls back to slower ones
     * Validates hash on retrieval
     * 
     * @param {string} hash - Event hash to retrieve
     * @returns {object} Event object
     */
    async retrieveEvent(hash) {
        let event = null;
        const attempts = [];
        
        // === 1. Try Redis first (fastest) ===
        try {
            const redisData = await this.redis.get(`event:${hash}`);
            if (redisData) {
                event = JSON.parse(redisData);
                attempts.push({ source: 'redis', success: true });
                
                // Validate hash matches
                if (await this.validateEventHash(event, hash)) {
                    return event;
                }
            }
        } catch (error) {
            attempts.push({ source: 'redis', error: error.message });
        }
        
        // === 2. Try S3/CDN (fast, reliable) ===
        if (!event) {
            try {
                const s3Result = await this.s3.getObject({
                    Bucket: this.bucket,
                    Key: `events/${hash}.json`
                }).promise();
                
                event = JSON.parse(s3Result.Body.toString());
                attempts.push({ source: 's3', success: true });
                
                // Cache in Redis for next time
                this.redis.set(`event:${hash}`, s3Result.Body.toString(), 'EX', 86400);
                
                // Validate hash
                if (await this.validateEventHash(event, hash)) {
                    return event;
                }
                
            } catch (error) {
                attempts.push({ source: 's3', error: error.message });
            }
        }
        
        // === 3. Try local cache ===
        if (!event) {
            try {
                const fs = require('fs').promises;
                const path = require('path');
                
                const filePath = path.join(this.localCachePath, `${hash}.json`);
                const fileData = await fs.readFile(filePath, 'utf8');
                event = JSON.parse(fileData);
                attempts.push({ source: 'local', success: true });
                
                // Validate hash
                if (await this.validateEventHash(event, hash)) {
                    return event;
                }
                
            } catch (error) {
                attempts.push({ source: 'local', error: error.message });
            }
        }
        
        // === 4. Try IPFS (slower but decentralized) ===
        if (!event) {
            try {
                // Try different retrieval methods
                const chunks = [];
                
                // First try by path
                try {
                    for await (const chunk of this.ipfs.cat(`/ipfs/${hash}.json`)) {
                        chunks.push(chunk);
                    }
                } catch {
                    // Try by CID if we have it stored
                    // This would require storing CID mapping
                }
                
                if (chunks.length > 0) {
                    const data = Buffer.concat(chunks).toString();
                    event = JSON.parse(data);
                    attempts.push({ source: 'ipfs', success: true });
                    
                    // Cache in faster storage
                    this.redis.set(`event:${hash}`, data, 'EX', 86400);
                    
                    // Validate hash
                    if (await this.validateEventHash(event, hash)) {
                        return event;
                    }
                }
                
            } catch (error) {
                attempts.push({ source: 'ipfs', error: error.message });
            }
        }
        
        // All retrieval attempts failed
        console.error('Event retrieval attempts:', attempts);
        throw new Error(`Event ${hash} not found in any storage location`);
    }
    
    /**
     * Validate that an event matches its expected hash
     * Prevents tampering and ensures integrity
     * 
     * @param {object} event - Event to validate
     * @param {string} expectedHash - Expected hash
     * @returns {boolean} True if valid
     */
    async validateEventHash(event, expectedHash) {
        try {
            // Remove signature for hash calculation
            const { sig, ...eventWithoutSig } = event;
            
            // Recreate canonical form
            const canonical = canonicalize(eventWithoutSig);
            const computedHash = createHash('sha256')
                .update(canonical)
                .digest('hex');
            
            if (computedHash !== expectedHash) {
                console.error(`Hash mismatch! Expected: ${expectedHash}, Got: ${computedHash}`);
                return false;
            }
            
            // Also verify signature if present
            if (sig && !this.verifyEventSignature(event)) {
                console.error('Invalid signature on event');
                return false;
            }
            
            return true;
            
        } catch (error) {
            console.error('Hash validation error:', error);
            return false;
        }
    }
    
    /**
     * Batch retrieve multiple events efficiently
     * Used when processing related events
     * 
     * @param {array} hashes - Array of event hashes
     * @returns {Map} Map of hash to event
     */
    async retrieveEvents(hashes) {
        const events = new Map();
        
        // Try to get all from Redis first (fastest)
        const pipeline = this.redis.pipeline();
        for (const hash of hashes) {
            pipeline.get(`event:${hash}`);
        }
        
        const results = await pipeline.exec();
        const missing = [];
        
        results.forEach((result, index) => {
            if (result[1]) {  // result is [error, value]
                try {
                    const event = JSON.parse(result[1]);
                    events.set(hashes[index], event);
                } catch (error) {
                    missing.push(hashes[index]);
                }
            } else {
                missing.push(hashes[index]);
            }
        });
        
        // Fetch missing events individually
        for (const hash of missing) {
            try {
                const event = await this.retrieveEvent(hash);
                events.set(hash, event);
            } catch (error) {
                console.error(`Failed to retrieve event ${hash}:`, error);
            }
        }
        
        return events;
    }
    
    /**
     * Archive events to cold storage
     * Used for older events to reduce storage costs
     * 
     * @param {Date} beforeDate - Archive events before this date
     */
    async archiveEvents(beforeDate) {
        // Implementation would:
        // 1. Query events before date
        // 2. Create CAR (Content Addressed Archive) files
        // 3. Upload to Glacier or Filecoin
        // 4. Remove from hot storage
        // 5. Keep index of archived events
        
        console.log('Archiving events before:', beforeDate);
        // TODO: Implement archival strategy
    }
    
    /**
     * Health check for all storage backends
     * Used for monitoring and alerting
     */
    async healthCheck() {
        const health = {
            redis: false,
            ipfs: false,
            s3: false,
            local: false,
            overall: false
        };
        
        // Test Redis
        try {
            await this.redis.ping();
            health.redis = true;
        } catch (error) {
            console.error('Redis health check failed:', error);
        }
        
        // Test IPFS
        try {
            const id = await this.ipfs.id();
            health.ipfs = !!id;
        } catch (error) {
            console.error('IPFS health check failed:', error);
        }
        
        // Test S3
        try {
            await this.s3.headBucket({ Bucket: this.bucket }).promise();
            health.s3 = true;
        } catch (error) {
            console.error('S3 health check failed:', error);
        }
        
        // Test local filesystem
        try {
            const fs = require('fs').promises;
            await fs.access(this.localCachePath);
            health.local = true;
        } catch (error) {
            console.error('Local storage health check failed:', error);
        }
        
        // Overall health (at least minRedundancy backends working)
        const workingCount = Object.values(health).filter(v => v).length;
        health.overall = workingCount >= this.minRedundancy;
        
        return health;
    }
    
    /**
     * Clean up connections and resources
     */
    async close() {
        await this.redis.quit();
        // IPFS and S3 don't need explicit cleanup
    }
}

/**
 * Event type definitions
 * Maps event types to numeric codes for on-chain storage
 */
const EventTypes = {
    // Release and content creation
    CREATE_RELEASE_BUNDLE: 21,
    CREATE_GROUP: 22,
    ADD_MEMBER: 23,
    REMOVE_MEMBER: 24,
    
    // Claims and edits
    ADD_CLAIM: 30,
    EDIT_CLAIM: 31,
    DELETE_CLAIM: 32,
    
    // Voting and curation
    VOTE: 40,
    LIKE: 41,
    DISCUSS: 42,
    
    // Finalization and rewards
    FINALIZE: 50,
    DISTRIBUTE_REWARDS: 51,
    
    // Deduplication
    MERGE_NODE: 60,
    SPLIT_NODE: 61
};

export { EventStore, EventTypes };
```

## Event Structure Examples

### CREATE_RELEASE_BUNDLE Event
```json
{
    "v": 1,
    "type": "CREATE_RELEASE_BUNDLE",
    "author_pubkey": "PUB_K1_...",
    "created_at": 1758390021,
    "parents": [],
    "body": {
        "release": {
            "name": "Abbey Road",
            "release_date": "1969-09-26",
            "format": ["LP", "CD"],
            "label_id": "label:parlophone"
        },
        "groups": [{
            "group_id": "group:beatles",
            "name": "The Beatles",
            "members": [
                {"person_id": "person:lennon", "role": "vocals", "instrument": "guitar"},
                {"person_id": "person:mccartney", "role": "vocals", "instrument": "bass"}
            ]
        }],
        "tracks": [{
            "title": "Come Together",
            "performed_by_group": {"group_id": "group:beatles"},
            "guests": []
        }],
        "tracklist": [{
            "track_id": "track:come-together",
            "disc": 1,
            "track_number": 1
        }]
    },
    "proofs": {
        "source_links": ["https://discogs.com/..."]
    },
    "sig": "SIG_K1_..."
}
```

### CREATE_GROUP Event
```json
{
    "v": 1,
    "type": "CREATE_GROUP",
    "author_pubkey": "PUB_K1_...",
    "created_at": 1758390021,
    "parents": [],
    "body": {
        "group": {
            "name": "Led Zeppelin",
            "formed_date": "1968-09-07",
            "origin_city": {
                "name": "London",
                "lat": 51.5074,
                "lon": -0.1278
            }
        },
        "founding_members": [
            {"name": "Jimmy Page", "role": "guitarist"},
            {"name": "Robert Plant", "role": "vocalist"},
            {"name": "John Paul Jones", "role": "bassist"},
            {"name": "John Bonham", "role": "drummer"}
        ]
    },
    "sig": "SIG_K1_..."
}
```

## Storage Architecture

```
┌─────────────────────────────────────────────┐
│                Event Creation                │
│         (Canonical JSON + SHA-256)           │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
        ┌─────────────────┐
        │   Sign Event    │
        │  (EOS PrivKey)  │
        └────────┬────────┘
                 │
    ┌────────────┼────────────┬──────────────┬──────────────┐
    ▼            ▼            ▼              ▼              ▼
┌────────┐ ┌────────┐ ┌────────┐    ┌────────┐    ┌────────┐
│ Redis  │ │  IPFS  │ │   S3   │    │ Local  │    │Archive │
│ (Hot)  │ │(Decentr│ │  (CDN) │    │ Cache  │    │(Glacier│
└────────┘ └────────┘ └────────┘    └────────┘    └────────┘
    │            │            │              │              │
    └────────────┼────────────┴──────────────┴──────────────┘
                 │
                 ▼
        ┌─────────────────┐
        │ Min Redundancy  │
        │    Achieved?    │
        └────────┬────────┘
                 │
                 ▼
         ┌──────────────┐
         │ Anchor Hash  │
         │  On-Chain    │
         └──────────────┘
```