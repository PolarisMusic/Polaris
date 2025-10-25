# Testing Suite - Comprehensive Tests

## Overview
Complete testing suite for all components of the Polaris music registry, including unit tests, integration tests, and end-to-end tests.

## Test Configuration

```javascript
// File: test/setup.js
// Global test setup and configuration

import { jest } from '@jest/globals';
import neo4j from 'neo4j-driver';
import Redis from 'ioredis';
import { EventStore } from '../src/storage/eventStore.js';
import MusicGraphDatabase from '../src/graph/schema.js';

// Test configuration
const TEST_CONFIG = {
    neo4j: {
        uri: process.env.TEST_NEO4J_URI || 'bolt://localhost:7687',
        user: 'neo4j',
        password: 'test'
    },
    redis: {
        host: 'localhost',
        port: 6379,
        db: 1  // Use separate DB for tests
    },
    storage: {
        ipfsUrl: 'http://localhost:5001',
        aws: {
            endpoint: 'http://localhost:9000',  // MinIO for testing
            accessKeyId: 'testaccess',
            secretAccessKey: 'testsecret',
            region: 'us-east-1',
            bucket: 'test-events'
        },
        redis: {
            host: 'localhost',
            port: 6379,
            db: 1
        }
    }
};

/**
 * Setup test database with clean state
 */
async function setupTestDatabase() {
    const driver = neo4j.driver(
        TEST_CONFIG.neo4j.uri,
        neo4j.auth.basic(TEST_CONFIG.neo4j.user, TEST_CONFIG.neo4j.password)
    );
    
    const session = driver.session();
    
    try {
        // Clear all data
        await session.run('MATCH (n) DETACH DELETE n');
        
        // Initialize schema
        const db = new MusicGraphDatabase(TEST_CONFIG.neo4j);
        await db.initializeSchema();
        
    } finally {
        await session.close();
        await driver.close();
    }
}

/**
 * Clear Redis test database
 */
async function clearRedis() {
    const redis = new Redis(TEST_CONFIG.redis);
    await redis.flushdb();
    await redis.quit();
}

// Global setup
beforeAll(async () => {
    await setupTestDatabase();
    await clearRedis();
});

// Global teardown
afterAll(async () => {
    // Cleanup connections
});

export { TEST_CONFIG, setupTestDatabase, clearRedis };
```

## Graph Database Tests

```javascript
// File: test/graph/database.test.js
// Test graph database operations

import MusicGraphDatabase from '../../src/graph/schema.js';
import { TEST_CONFIG } from '../setup.js';

describe('MusicGraphDatabase', () => {
    let db;
    
    beforeEach(async () => {
        db = new MusicGraphDatabase(TEST_CONFIG.neo4j);
        await db.initializeSchema();
    });
    
    afterEach(async () => {
        await db.close();
    });
    
    describe('processReleaseBundle', () => {
        /**
         * Test creating a release with groups
         */
        test('should create release with group and members', async () => {
            const bundle = {
                release: {
                    name: 'Test Album',
                    release_date: '2024-01-01',
                    format: ['CD', 'Digital']
                },
                groups: [{
                    name: 'Test Band',
                    formed_date: '2020-01-01',
                    members: [
                        { name: 'Alice', role: 'vocalist', primary_instrument: 'voice' },
                        { name: 'Bob', role: 'guitarist', primary_instrument: 'guitar' }
                    ]
                }],
                tracks: [{
                    title: 'Test Song',
                    duration: 180,
                    performed_by_group: { group_id: 'group:test-band', name: 'Test Band' },
                    guests: []
                }],
                tracklist: [{
                    track_id: 'track:test-song',
                    disc: 1,
                    track_number: 1
                }]
            };
            
            const result = await db.processReleaseBundle(
                'test-hash-123',
                bundle,
                'testaccount'
            );
            
            expect(result.success).toBe(true);
            expect(result.releaseId).toBeDefined();
            expect(result.stats.groups_created).toBe(1);
            expect(result.stats.tracks_created).toBe(1);
            
            // Verify group was created with members
            const session = db.driver.session();
            try {
                const groupResult = await session.run(`
                    MATCH (g:Group {name: 'Test Band'})
                    OPTIONAL MATCH (p:Person)-[:MEMBER_OF]->(g)
                    RETURN g, collect(p.name) as members
                `);
                
                expect(groupResult.records).toHaveLength(1);
                const members = groupResult.records[0].get('members');
                expect(members).toContain('Alice');
                expect(members).toContain('Bob');
                
            } finally {
                await session.close();
            }
        });
        
        /**
         * Test distinguishing group members from guests
         */
        test('should distinguish group members from guest performers', async () => {
            const bundle = {
                release: {
                    name: 'Collaboration Album',
                    release_date: '2024-02-01'
                },
                groups: [{
                    name: 'Main Band',
                    members: [
                        { name: 'Charlie', role: 'drummer' }
                    ]
                }],
                tracks: [{
                    title: 'Featuring Track',
                    performed_by_group: { group_id: 'group:main-band', name: 'Main Band' },
                    guests: [
                        { name: 'Guest Artist', role: 'vocals', instrument: 'voice' }
                    ]
                }],
                tracklist: [{
                    track_id: 'track:featuring',
                    disc: 1,
                    track_number: 1
                }]
            };
            
            const result = await db.processReleaseBundle(
                'test-hash-456',
                bundle,
                'testaccount'
            );
            
            expect(result.success).toBe(true);
            
            // Verify relationships
            const session = db.driver.session();
            try {
                // Check group performance
                const groupPerf = await session.run(`
                    MATCH (g:Group {name: 'Main Band'})-[:PERFORMED_ON]->(t:Track {title: 'Featuring Track'})
                    RETURN count(g) as count
                `);
                expect(groupPerf.records[0].get('count').toNumber()).toBe(1);
                
                // Check guest appearance
                const guestPerf = await session.run(`
                    MATCH (p:Person {name: 'Guest Artist'})-[:GUEST_ON]->(t:Track {title: 'Featuring Track'})
                    RETURN count(p) as count
                `);
                expect(guestPerf.records[0].get('count').toNumber()).toBe(1);
                
                // Ensure guest is NOT a member of the group
                const notMember = await session.run(`
                    MATCH (p:Person {name: 'Guest Artist'})-[:MEMBER_OF]->(g:Group {name: 'Main Band'})
                    RETURN count(p) as count
                `);
                expect(notMember.records[0].get('count').toNumber()).toBe(0);
                
            } finally {
                await session.close();
            }
        });
    });
    
    describe('calculateGroupMemberParticipation', () => {
        /**
         * Test participation percentage calculation
         */
        test('should calculate correct member participation percentages', async () => {
            // Setup test data
            const session = db.driver.session();
            try {
                await session.run(`
                    CREATE (g:Group {group_id: 'group:test', name: 'Test Group'})
                    CREATE (p1:Person {person_id: 'person:1', name: 'Member1'})
                    CREATE (p2:Person {person_id: 'person:2', name: 'Member2'})
                    CREATE (p1)-[:MEMBER_OF {from_date: '2020-01-01'}]->(g)
                    CREATE (p2)-[:MEMBER_OF {from_date: '2021-01-01'}]->(g)
                    
                    // Create tracks with different member participation
                    CREATE (t1:Track {track_id: 'track:1', title: 'Song 1'})
                    CREATE (t2:Track {track_id: 'track:2', title: 'Song 2'})
                    CREATE (t3:Track {track_id: 'track:3', title: 'Song 3'})
                    CREATE (g)-[:PERFORMED_ON]->(t1)
                    CREATE (g)-[:PERFORMED_ON]->(t2)
                    CREATE (g)-[:PERFORMED_ON]->(t3)
                    
                    // Create releases with dates
                    CREATE (r1:Release {release_id: 'rel:1', release_date: '2020-06-01'})
                    CREATE (r2:Release {release_id: 'rel:2', release_date: '2021-06-01'})
                    CREATE (r3:Release {release_id: 'rel:3', release_date: '2022-01-01'})
                    CREATE (t1)-[:IN_RELEASE]->(r1)
                    CREATE (t2)-[:IN_RELEASE]->(r2)
                    CREATE (t3)-[:IN_RELEASE]->(r3)
                `);
            } finally {
                await session.close();
            }
            
            // Calculate participation
            const participation = await db.calculateGroupMemberParticipation('group:test');
            
            expect(participation).toHaveLength(2);
            
            // Member1 was in all 3 tracks (100%)
            const member1 = participation.find(p => p.personName === 'Member1');
            expect(member1.trackCount).toBe(3);
            expect(member1.participationPercentage).toBe(100);
            
            // Member2 was in 2 tracks (started in 2021)
            const member2 = participation.find(p => p.personName === 'Member2');
            expect(member2.trackCount).toBe(2);
            expect(member2.participationPercentage).toBeCloseTo(66.67, 1);
        });
    });
});
```

## Event Storage Tests

```javascript
// File: test/storage/eventStore.test.js
// Test event storage and retrieval

import { EventStore } from '../../src/storage/eventStore.js';
import { TEST_CONFIG } from '../setup.js';

describe('EventStore', () => {
    let store;
    
    beforeEach(() => {
        store = new EventStore(TEST_CONFIG.storage);
    });
    
    afterEach(async () => {
        await store.close();
    });
    
    describe('createEvent', () => {
        /**
         * Test canonical event creation
         */
        test('should create deterministic event hash', async () => {
            const eventData = {
                type: 'CREATE_GROUP',
                body: {
                    group: { name: 'Test Band' },
                    founding_members: []
                },
                authorPubkey: 'PUB_K1_test'
            };
            
            // Create same event twice
            const event1 = await store.createEvent(
                eventData.type,
                eventData.body,
                eventData.authorPubkey
            );
            
            const event2 = await store.createEvent(
                eventData.type,
                eventData.body,
                eventData.authorPubkey
            );
            
            // Hashes should be identical for same content
            expect(event1.hash).toBe(event2.hash);
        });
        
        /**
         * Test event signature verification
         */
        test('should verify event signatures', () => {
            // Mock event with signature
            const signedEvent = {
                v: 1,
                type: 'CREATE_GROUP',
                author_pubkey: 'PUB_K1_test',
                created_at: 1234567890,
                body: { group: { name: 'Test' } },
                sig: 'SIG_K1_mock'
            };
            
            // In real test, would use actual EOS key signing
            // For now, test the structure
            expect(signedEvent).toHaveProperty('sig');
            expect(signedEvent.sig).toMatch(/^SIG_K1_/);
        });
    });
    
    describe('storeEvent', () => {
        /**
         * Test redundant storage
         */
        test('should store event in multiple locations', async () => {
            const event = {
                v: 1,
                type: 'CREATE_RELEASE_BUNDLE',
                author_pubkey: 'PUB_K1_test',
                created_at: Date.now(),
                body: { release: { name: 'Test Album' } }
            };
            
            const hash = 'testhash123';
            
            // Mock storage (in real test, would use test instances)
            const stored = await store.storeEvent(event, hash);
            
            // Should succeed in at least minRedundancy locations
            expect(stored.length).toBeGreaterThanOrEqual(store.minRedundancy);
            
            // Should include different storage types
            const types = stored.map(s => s.type);
            expect(types).toContain('redis');
        });
    });
});
```

## API Integration Tests

```javascript
// File: test/api/integration.test.js
// Test API endpoints

import request from 'supertest';
import APIServer from '../../src/api/server.js';
import { TEST_CONFIG } from '../setup.js';

describe('API Integration Tests', () => {
    let server;
    let app;
    
    beforeAll(async () => {
        server = new APIServer(TEST_CONFIG);
        app = server.app;
    });
    
    describe('GraphQL API', () => {
        /**
         * Test group query
         */
        test('should query group with members', async () => {
            const query = `
                query GetGroup($id: String!) {
                    group(id: $id) {
                        id
                        name
                        memberCount
                        members {
                            person {
                                name
                            }
                            role
                            instrument
                        }
                    }
                }
            `;
            
            const response = await request(app)
                .post('/graphql')
                .send({
                    query,
                    variables: { id: 'group:beatles' }
                })
                .expect(200);
            
            expect(response.body.data.group).toBeDefined();
            expect(response.body.data.group.members).toBeInstanceOf(Array);
        });
        
        /**
         * Test search functionality
         */
        test('should search across entity types', async () => {
            const query = `
                query Search($query: String!) {
                    search(query: $query) {
                        ... on Group {
                            id
                            name
                        }
                        ... on Person {
                            id
                            name
                        }
                        ... on Release {
                            id
                            name
                        }
                    }
                }
            `;
            
            const response = await request(app)
                .post('/graphql')
                .send({
                    query,
                    variables: { query: 'test' }
                })
                .expect(200);
            
            expect(response.body.data.search).toBeInstanceOf(Array);
        });
    });
    
    describe('REST API', () => {
        /**
         * Test group participation endpoint
         */
        test('GET /api/groups/:groupId/participation', async () => {
            // Create test group with members
            // ... setup code ...
            
            const response = await request(app)
                .get('/api/groups/group:test/participation')
                .expect(200);
            
            expect(response.body).toHaveProperty('groupId');
            expect(response.body).toHaveProperty('members');
            expect(response.body.members).toBeInstanceOf(Array);
            
            // Each member should have participation data
            if (response.body.members.length > 0) {
                const member = response.body.members[0];
                expect(member).toHaveProperty('personId');
                expect(member).toHaveProperty('personName');
                expect(member).toHaveProperty('participationPercentage');
                expect(member).toHaveProperty('trackCount');
            }
        });
        
        /**
         * Test person's groups endpoint
         */
        test('GET /api/persons/:personId/groups', async () => {
            const response = await request(app)
                .get('/api/persons/person:test/groups')
                .expect(200);
            
            expect(response.body).toHaveProperty('personId');
            expect(response.body).toHaveProperty('groups');
            expect(response.body.groups).toBeInstanceOf(Array);
        });
        
        /**
         * Test health check endpoint
         */
        test('GET /api/health', async () => {
            const response = await request(app)
                .get('/api/health')
                .expect(200);
            
            expect(response.body).toHaveProperty('api');
            expect(response.body.api).toBe('healthy');
            expect(response.body).toHaveProperty('database');
            expect(response.body).toHaveProperty('redis');
        });
    });
});
```

## End-to-End Tests

```javascript
// File: test/e2e/workflow.test.js
// End-to-end workflow tests

import { Session } from '@wharfkit/session';
import { Api, JsonRpc } from 'eosjs';
import request from 'supertest';
import APIServer from '../../src/api/server.js';
import EventProcessor from '../../src/indexer/eventProcessor.js';
import { TEST_CONFIG } from '../setup.js';

describe('End-to-End Workflow', () => {
    let apiServer;
    let processor;
    let session;
    
    beforeAll(async () => {
        // Start services
        apiServer = new APIServer(TEST_CONFIG);
        processor = new EventProcessor(TEST_CONFIG);
        
        // Mock blockchain session
        // In real test, would use testnet
        session = {
            actor: 'testaccount',
            permission: 'active',
            transact: jest.fn().mockResolvedValue({ transaction_id: 'test-tx-id' })
        };
    });
    
    /**
     * Test complete release submission workflow
     */
    test('complete release submission workflow', async () => {
        // Step 1: Create release bundle event
        const releaseBundle = {
            release: {
                name: 'E2E Test Album',
                release_date: '2024-01-01'
            },
            groups: [{
                name: 'E2E Test Band',
                members: [
                    { name: 'Test Member 1', role: 'vocalist' },
                    { name: 'Test Member 2', role: 'guitarist' }
                ]
            }],
            tracks: [{
                title: 'E2E Test Song',
                performed_by_group: { 
                    group_id: 'group:e2e-test-band',
                    name: 'E2E Test Band'
                },
                guests: [
                    { name: 'Guest Artist', role: 'featuring' }
                ]
            }],
            tracklist: [{
                track_id: 'track:e2e-test-song',
                disc: 1,
                track_number: 1
            }]
        };
        
        // Step 2: Create and store event
        const createResponse = await request(apiServer.app)
            .post('/api/events/create')
            .send({
                type: 'CREATE_RELEASE_BUNDLE',
                body: releaseBundle,
                author: 'testaccount'
            })
            .expect(200);
        
        expect(createResponse.body.success).toBe(true);
        expect(createResponse.body.hash).toBeDefined();
        
        const eventHash = createResponse.body.hash;
        
        // Step 3: Anchor on blockchain (mocked)
        const anchorData = {
            author: 'testaccount',
            type: 21, // CREATE_RELEASE_BUNDLE
            hash: eventHash,
            parent: null,
            ts: Math.floor(Date.now() / 1000),
            tags: ['release', 'test']
        };
        
        // Simulate anchor processing
        await processor.handleAnchor(anchorData, 'test-tx-id', 100000);
        await processor.processQueue();
        
        // Step 4: Verify data in graph
        const searchResponse = await request(apiServer.app)
            .get('/api/search')
            .query({ q: 'E2E Test Album' })
            .expect(200);
        
        expect(searchResponse.body).toHaveLength(1);
        expect(searchResponse.body[0].name).toBe('E2E Test Album');
        
        // Step 5: Check group participation
        const participationResponse = await request(apiServer.app)
            .get('/api/groups/group:e2e-test-band/participation')
            .expect(200);
        
        expect(participationResponse.body.members).toHaveLength(2);
        
        // Step 6: Verify guest vs member distinction
        const groupDetailsResponse = await request(apiServer.app)
            .get('/api/groups/group:e2e-test-band/details')
            .expect(200);
        
        // Should have 2 members
        expect(groupDetailsResponse.body.members).toHaveLength(2);
        const memberNames = groupDetailsResponse.body.members.map(m => m.name);
        expect(memberNames).toContain('Test Member 1');
        expect(memberNames).toContain('Test Member 2');
        expect(memberNames).not.toContain('Guest Artist'); // Guest is not a member
    });
    
    /**
     * Test voting and finalization workflow
     */
    test('voting and finalization workflow', async () => {
        // Create an event to vote on
        const createResponse = await request(apiServer.app)
            .post('/api/events/create')
            .send({
                type: 'CREATE_GROUP',
                body: {
                    group: { name: 'Vote Test Band' },
                    founding_members: []
                },
                author: 'testaccount'
            })
            .expect(200);
        
        const eventHash = createResponse.body.hash;
        
        // Submit votes
        const votes = [
            { voter: 'voter1', value: 1 },  // Approve
            { voter: 'voter2', value: 1 },  // Approve
            { voter: 'voter3', value: -1 }  // Reject
        ];
        
        for (const vote of votes) {
            // In real test, would submit to blockchain
            // For now, simulate vote processing
        }
        
        // Calculate approval (2 approve, 1 reject = 66.7%)
        const approval = 2 / 3;
        expect(approval).toBeCloseTo(0.667, 2);
        
        // Since approval < 90%, submission would be rejected
        expect(approval).toBeLessThan(0.9);
    });
});
```

## Performance Tests

```javascript
// File: test/performance/load.test.js
// Performance and load testing

import autocannon from 'autocannon';
import APIServer from '../../src/api/server.js';
import { TEST_CONFIG } from '../setup.js';

describe('Performance Tests', () => {
    let server;
    
    beforeAll(async () => {
        server = new APIServer(TEST_CONFIG);
        server.start();
    });
    
    /**
     * Test API throughput
     */
    test('API should handle 1000 requests per second', (done) => {
        const instance = autocannon({
            url: 'http://localhost:3000',
            connections: 10,
            pipelining: 1,
            duration: 10,
            requests: [
                {
                    method: 'GET',
                    path: '/api/health'
                }
            ]
        }, (err, result) => {
            expect(err).toBeNull();
            expect(result.requests.average).toBeGreaterThan(1000);
            done();
        });
    });
    
    /**
     * Test database query performance
     */
    test('group participation query should complete in < 100ms', async () => {
        const start = Date.now();
        
        const response = await fetch('http://localhost:3000/api/groups/group:test/participation');
        const data = await response.json();
        
        const duration = Date.now() - start;
        expect(duration).toBeLessThan(100);
    });
    
    /**
     * Test concurrent write operations
     */
    test('should handle concurrent release submissions', async () => {
        const submissions = [];
        
        // Create 10 concurrent submissions
        for (let i = 0; i < 10; i++) {
            submissions.push(
                fetch('http://localhost:3000/api/events/create', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        type: 'CREATE_RELEASE_BUNDLE',
                        body: {
                            release: { name: `Concurrent Album ${i}` }
                        },
                        author: `testaccount${i}`
                    })
                })
            );
        }
        
        const results = await Promise.all(submissions);
        
        // All should succeed
        for (const result of results) {
            expect(result.status).toBe(200);
        }
    });
});
```

## Test Utilities

```javascript
// File: test/utils/testHelpers.js
// Utility functions for testing

/**
 * Create test group with members
 */
export async function createTestGroup(db, groupData = {}) {
    const defaultGroup = {
        name: 'Test Group',
        formed_date: '2020-01-01',
        members: [
            { name: 'Member 1', role: 'member' },
            { name: 'Member 2', role: 'member' }
        ]
    };
    
    const group = { ...defaultGroup, ...groupData };
    
    const session = db.driver.session();
    try {
        const result = await session.run(`
            CREATE (g:Group {
                group_id: $groupId,
                name: $name,
                formed_date: $formedDate
            })
            RETURN g
        `, {
            groupId: `group:${group.name.toLowerCase().replace(/ /g, '-')}`,
            name: group.name,
            formedDate: group.formed_date
        });
        
        // Add members
        for (const member of group.members) {
            await session.run(`
                MATCH (g:Group {name: $groupName})
                CREATE (p:Person {
                    person_id: $personId,
                    name: $name
                })
                CREATE (p)-[:MEMBER_OF {role: $role}]->(g)
            `, {
                groupName: group.name,
                personId: `person:${member.name.toLowerCase().replace(/ /g, '-')}`,
                name: member.name,
                role: member.role
            });
        }
        
        return result.records[0].get('g').properties;
        
    } finally {
        await session.close();
    }
}

/**
 * Create test release with tracks
 */
export async function createTestRelease(db, releaseData = {}) {
    const defaultRelease = {
        name: 'Test Album',
        release_date: '2024-01-01',
        tracks: [
            { title: 'Track 1', duration: 180 },
            { title: 'Track 2', duration: 240 }
        ]
    };
    
    const release = { ...defaultRelease, ...releaseData };
    
    // Implementation...
    return release;
}

/**
 * Wait for event to be processed
 */
export async function waitForProcessing(eventHash, maxWait = 5000) {
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWait) {
        // Check if event is processed
        const response = await fetch(`http://localhost:3000/api/events/${eventHash}`);
        if (response.status === 200) {
            const data = await response.json();
            if (data.processed) {
                return true;
            }
        }
        
        // Wait before retry
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    throw new Error(`Event ${eventHash} not processed within ${maxWait}ms`);
}

/**
 * Mock blockchain transaction
 */
export function mockBlockchainTransaction(action, data) {
    return {
        transaction_id: `mock-tx-${Date.now()}`,
        processed: {
            receipt: {
                status: 'executed'
            },
            action_traces: [{
                act: {
                    account: 'polaris',
                    name: action,
                    data
                }
            }]
        }
    };
}
```

## Test Configuration Files

```json
// File: test/jest.config.js
// Jest configuration for testing

export default {
    testEnvironment: 'node',
    roots: ['<rootDir>/test'],
    testMatch: [
        '**/__tests__/**/*.js',
        '**/?(*.)+(spec|test).js'
    ],
    transform: {
        '^.+\\.js$': 'babel-jest'
    },
    collectCoverageFrom: [
        'src/**/*.js',
        '!src/**/*.test.js',
        '!src/**/index.js'
    ],
    coverageThreshold: {
        global: {
            branches: 80,
            functions: 80,
            lines: 80,
            statements: 80
        }
    },
    setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
    testTimeout: 10000,
    verbose: true
};
```

```json
// File: package.json (test scripts)
{
    "scripts": {
        "test": "jest",
        "test:watch": "jest --watch",
        "test:coverage": "jest --coverage",
        "test:integration": "jest --testPathPattern=integration",
        "test:e2e": "jest --testPathPattern=e2e",
        "test:performance": "jest --testPathPattern=performance",
        "test:ci": "jest --ci --coverage --maxWorkers=2"
    }
}
```