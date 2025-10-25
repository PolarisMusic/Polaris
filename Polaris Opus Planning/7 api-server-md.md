# API Server - GraphQL and REST Endpoints

## Overview
Express server providing both GraphQL and REST endpoints for the music registry. Handles Groups, member participation calculations, and all graph queries.

## Main Server Implementation

```javascript
// File: backend/src/api/server.js
// Express server with GraphQL and REST endpoints for music data

import express from 'express';
import { graphqlHTTP } from 'express-graphql';
import { buildSchema } from 'graphql';
import cors from 'cors';
import Redis from 'ioredis';
import EventStore from '../storage/eventStore.js';
import MusicGraphDatabase from '../graph/schema.js';
import EventProcessor from '../indexer/eventProcessor.js';

class APIServer {
    constructor(config) {
        /**
         * Initialize API server with all dependencies
         */
        
        this.app = express();
        this.port = config.port || 3000;
        
        // Initialize data stores
        this.eventStore = new EventStore(config.storage);
        this.graphDb = new MusicGraphDatabase(config.neo4j);
        this.redis = new Redis(config.redis);
        
        // GraphQL schema
        this.schema = this.buildGraphQLSchema();
        
        // Setup middleware and routes
        this.setupMiddleware();
        this.setupRoutes();
    }
    
    /**
     * Configure Express middleware
     */
    setupMiddleware() {
        // CORS for frontend access
        this.app.use(cors({
            origin: ['http://localhost:3001', 'https://app.polaris.music'],
            credentials: true
        }));
        
        // JSON parsing
        this.app.use(express.json({ limit: '10mb' }));
        
        // Request logging
        this.app.use((req, res, next) => {
            console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
            next();
        });
        
        // Error handling
        this.app.use((err, req, res, next) => {
            console.error('Error:', err);
            res.status(500).json({ 
                error: 'Internal server error',
                message: err.message 
            });
        });
    }
    
    /**
     * Build GraphQL schema with all types and resolvers
     */
    buildGraphQLSchema() {
        const schema = buildSchema(`
            # ========== CORE TYPES ==========
            
            type Group {
                id: String!
                name: String!
                altNames: [String]
                bio: String
                formedDate: String
                disbandedDate: String
                memberCount: Int
                activeMemberCount: Int
                members: [Member]
                releases: [Release]
                tracks: [Track]
                participation: ParticipationData
                origin: City
            }
            
            type Person {
                id: String!
                name: String!
                bio: String
                groups: [GroupMembership]
                guestAppearances: [Track]
                songsWritten: [Song]
                origin: City
            }
            
            type Member {
                person: Person!
                role: String
                instrument: String
                fromDate: String
                toDate: String
                isFoundingMember: Boolean
                participationPercentage: Float
                trackCount: Int
            }
            
            type GroupMembership {
                group: Group!
                role: String
                instrument: String
                fromDate: String
                toDate: String
                isActive: Boolean
            }
            
            type Release {
                id: String!
                name: String!
                altNames: [String]
                releaseDate: String
                format: [String]
                albumArt: String
                tracks: [Track]
                label: Label
                master: Master
            }
            
            type Track {
                id: String!
                title: String!
                duration: Int
                isrc: String
                performedByGroup: Group
                guests: [Person]
                recording: Song
                samples: [Track]
                inRelease: Release
            }
            
            type Song {
                id: String!
                title: String!
                iswc: String
                writers: [Person]
                recordings: [Track]
            }
            
            type Label {
                id: String!
                name: String!
                releases: [Release]
                location: City
            }
            
            type Master {
                id: String!
                name: String!
                releases: [Release]
            }
            
            type City {
                id: String!
                name: String!
                lat: Float
                lon: Float
                groups: [Group]
                persons: [Person]
            }
            
            type Account {
                id: String!
                submissions: [Submission]
                stakes: [Stake]
                votes: [Vote]
            }
            
            # ========== PARTICIPATION DATA ==========
            
            type ParticipationData {
                groupId: String!
                members: [MemberParticipation]!
                totalMembers: Int!
                totalTracks: Int!
            }
            
            type MemberParticipation {
                personId: String!
                personName: String!
                trackCount: Int!
                participationPercentage: Float!
                releaseCount: Int!
            }
            
            # ========== SUBMISSIONS & VOTING ==========
            
            type Submission {
                hash: String!
                type: String!
                author: String!
                timestamp: Int!
                finalized: Boolean!
                votes: VoteStats
            }
            
            type VoteStats {
                upVotes: Int!
                downVotes: Int!
                approval: Float!
            }
            
            type Vote {
                voter: String!
                value: Int!
                weight: Int!
            }
            
            type Stake {
                nodeId: String!
                amount: String!
                stakedAt: String!
            }
            
            # ========== SEARCH RESULTS ==========
            
            union SearchResult = Group | Person | Release | Track | Song
            
            # ========== QUERIES ==========
            
            type Query {
                # Groups
                group(id: String!): Group
                groups(limit: Int, active: Boolean): [Group]
                groupParticipation(groupId: String!): ParticipationData
                
                # Persons
                person(id: String!): Person
                persons(limit: Int): [Person]
                personGroups(personId: String!): [GroupMembership]
                
                # Releases and Tracks
                release(id: String!): Release
                recentReleases(limit: Int): [Release]
                track(id: String!): Track
                
                # Search
                search(query: String!, type: String): [SearchResult]
                
                # Graph data
                graphInitial: GraphData
                nodeDetails(id: String!): NodeDetails
                
                # Submissions
                submission(hash: String!): Submission
                recentSubmissions(limit: Int): [Submission]
            }
            
            # ========== MUTATIONS ==========
            
            type Mutation {
                # Event creation
                createEvent(type: String!, body: JSON!): EventResult
                
                # Voting
                vote(targetHash: String!, verdict: String!): VoteResult
                
                # Staking
                stake(nodeId: String!, amount: String!): StakeResult
                unstake(nodeId: String!, amount: String!): StakeResult
            }
            
            # ========== RESPONSE TYPES ==========
            
            type EventResult {
                success: Boolean!
                hash: String
                error: String
            }
            
            type VoteResult {
                success: Boolean!
                error: String
            }
            
            type StakeResult {
                success: Boolean!
                newTotal: String
                error: String
            }
            
            type GraphData {
                nodes: [GraphNode]!
                relationships: [GraphRelationship]!
            }
            
            type GraphNode {
                id: String!
                labels: [String]!
                properties: JSON!
            }
            
            type GraphRelationship {
                id: String!
                type: String!
                start: String!
                end: String!
                properties: JSON
            }
            
            type NodeDetails {
                node: GraphNode!
                connections: [Connection]!
            }
            
            type Connection {
                relationship: String!
                direction: String!
                node: GraphNode!
            }
            
            # JSON scalar for flexible data
            scalar JSON
        `);
        
        return schema;
    }
    
    /**
     * Setup all API routes
     */
    setupRoutes() {
        // ========== GraphQL Endpoint ==========
        
        this.app.use('/graphql', graphqlHTTP({
            schema: this.schema,
            rootValue: this.createResolvers(),
            graphiql: true // Enable GraphQL playground
        }));
        
        // ========== REST Endpoints ==========
        
        // === Groups ===
        
        /**
         * Get group participation data for RGraph visualization
         */
        this.app.get('/api/groups/:groupId/participation', async (req, res) => {
            try {
                const { groupId } = req.params;
                const participation = await this.graphDb.calculateGroupMemberParticipation(groupId);
                
                res.json({
                    groupId,
                    members: participation,
                    totalMembers: participation.length
                });
                
            } catch (error) {
                console.error('Error getting participation:', error);
                res.status(500).json({ error: error.message });
            }
        });
        
        /**
         * Get detailed group information including timeline
         */
        this.app.get('/api/groups/:groupId/details', async (req, res) => {
            try {
                const { groupId } = req.params;
                const session = this.graphDb.driver.session();
                
                const result = await session.run(`
                    MATCH (g:Group {group_id: $groupId})
                    
                    // Basic group info
                    OPTIONAL MATCH (g)-[:PERFORMED_ON]->(track:Track)
                    OPTIONAL MATCH (track)-[:IN_RELEASE]->(release:Release)
                    
                    WITH g, 
                         count(DISTINCT track) as trackCount,
                         count(DISTINCT release) as releaseCount,
                         min(date(release.release_date)) as earliestRelease,
                         max(date(release.release_date)) as latestRelease
                    
                    // Get all members with periods
                    OPTIONAL MATCH (person:Person)-[membership:MEMBER_OF]->(g)
                    
                    // Get origin city
                    OPTIONAL MATCH (g)-[:ORIGIN]->(city:City)
                    
                    RETURN g.group_id as id,
                           g.name as name,
                           g.bio as bio,
                           g.formed_date as formedDate,
                           g.disbanded_date as disbandedDate,
                           trackCount,
                           releaseCount,
                           earliestRelease,
                           latestRelease,
                           city.name as originCity,
                           collect({
                               personId: person.person_id,
                               name: person.name,
                               role: membership.role,
                               instrument: membership.primary_instrument,
                               fromDate: membership.from_date,
                               toDate: membership.to_date,
                               foundingMember: membership.founding_member
                           }) as members
                `, { groupId });
                
                await session.close();
                
                if (result.records.length === 0) {
                    return res.status(404).json({ error: 'Group not found' });
                }
                
                const record = result.records[0];
                const groupDetails = {
                    id: record.get('id'),
                    name: record.get('name'),
                    bio: record.get('bio'),
                    formedDate: record.get('formedDate'),
                    disbandedDate: record.get('disbandedDate'),
                    trackCount: record.get('trackCount').toNumber(),
                    releaseCount: record.get('releaseCount').toNumber(),
                    earliestRelease: record.get('earliestRelease'),
                    latestRelease: record.get('latestRelease'),
                    originCity: record.get('originCity'),
                    members: record.get('members').filter(m => m.personId !== null)
                };
                
                res.json(groupDetails);
                
            } catch (error) {
                console.error('Error getting group details:', error);
                res.status(500).json({ error: error.message });
            }
        });
        
        // === Persons ===
        
        /**
         * Get person's group connections for edge coloring
         */
        this.app.get('/api/persons/:personId/groups', async (req, res) => {
            try {
                const { personId } = req.params;
                const session = this.graphDb.driver.session();
                
                const result = await session.run(`
                    MATCH (p:Person {person_id: $personId})
                    MATCH (p)-[membership:MEMBER_OF]->(g:Group)
                    
                    // Get participation stats
                    OPTIONAL MATCH (g)-[:PERFORMED_ON]->(track:Track)
                    WHERE EXISTS((p)-[:MEMBER_OF]->(g))
                    
                    WITH p, g, membership, count(track) as trackCount
                    
                    // Get guest appearances
                    OPTIONAL MATCH (p)-[guest:GUEST_ON]->(guestTrack:Track)
                    
                    RETURN g.group_id as groupId,
                           g.name as groupName,
                           membership.role as role,
                           membership.primary_instrument as instrument,
                           membership.from_date as fromDate,
                           membership.to_date as toDate,
                           trackCount,
                           CASE 
                               WHEN membership.to_date IS NULL THEN true 
                               ELSE false 
                           END as isCurrentMember,
                           count(guestTrack) as guestAppearances
                    ORDER BY isCurrentMember DESC, trackCount DESC
                `, { personId });
                
                await session.close();
                
                const groups = result.records.map(record => ({
                    groupId: record.get('groupId'),
                    groupName: record.get('groupName'),
                    role: record.get('role'),
                    instrument: record.get('instrument'),
                    fromDate: record.get('fromDate'),
                    toDate: record.get('toDate'),
                    trackCount: record.get('trackCount').toNumber(),
                    isCurrentMember: record.get('isCurrentMember'),
                    guestAppearances: record.get('guestAppearances').toNumber()
                }));
                
                res.json({ personId, groups });
                
            } catch (error) {
                console.error('Error getting person groups:', error);
                res.status(500).json({ error: error.message });
            }
        });
        
        // === Graph Data ===
        
        /**
         * Get initial graph data for visualization
         */
        this.app.get('/api/graph/initial', async (req, res) => {
            try {
                const session = this.graphDb.driver.session();
                
                // Get top-level nodes and relationships
                const result = await session.run(`
                    // Get prominent groups
                    MATCH (g:Group)
                    WHERE g.member_count > 0
                    WITH g
                    ORDER BY g.track_count DESC
                    LIMIT 20
                    
                    // Get their members
                    OPTIONAL MATCH (p:Person)-[m:MEMBER_OF]->(g)
                    
                    // Get recent releases
                    OPTIONAL MATCH (g)-[:PERFORMED_ON]->(t:Track)-[:IN_RELEASE]->(r:Release)
                    
                    // Collect all nodes and relationships
                    WITH collect(DISTINCT g) as groups,
                         collect(DISTINCT p) as persons,
                         collect(DISTINCT r) as releases,
                         collect(DISTINCT {start: p.person_id, end: g.group_id, type: 'MEMBER_OF'}) as memberships,
                         collect(DISTINCT {start: g.group_id, end: r.release_id, type: 'RELEASED'}) as releaseRels
                    
                    RETURN groups, persons, releases, memberships, releaseRels
                `);
                
                await session.close();
                
                // Transform to visualization format
                const nodes = [];
                const relationships = [];
                let nodeIdCounter = 1;
                
                const record = result.records[0];
                
                // Add groups
                for (const group of record.get('groups')) {
                    if (group) {
                        nodes.push({
                            id: group.properties.group_id,
                            labels: ['Group'],
                            properties: group.properties
                        });
                    }
                }
                
                // Add persons
                for (const person of record.get('persons')) {
                    if (person) {
                        nodes.push({
                            id: person.properties.person_id,
                            labels: ['Person'],
                            properties: person.properties
                        });
                    }
                }
                
                // Add releases (limited)
                const releases = record.get('releases').slice(0, 10);
                for (const release of releases) {
                    if (release) {
                        nodes.push({
                            id: release.properties.release_id,
                            labels: ['Release'],
                            properties: release.properties
                        });
                    }
                }
                
                // Add relationships
                for (const rel of record.get('memberships')) {
                    if (rel.start && rel.end) {
                        relationships.push({
                            id: `rel-${nodeIdCounter++}`,
                            type: rel.type,
                            start: rel.start,
                            end: rel.end
                        });
                    }
                }
                
                for (const rel of record.get('releaseRels')) {
                    if (rel.start && rel.end) {
                        relationships.push({
                            id: `rel-${nodeIdCounter++}`,
                            type: rel.type,
                            start: rel.start,
                            end: rel.end
                        });
                    }
                }
                
                res.json({ nodes, relationships });
                
            } catch (error) {
                console.error('Error getting graph data:', error);
                res.status(500).json({ error: error.message });
            }
        });
        
        // === Search ===
        
        /**
         * Search across all entity types
         */
        this.app.get('/api/search', async (req, res) => {
            try {
                const { q, type } = req.query;
                
                if (!q) {
                    return res.status(400).json({ error: 'Query parameter required' });
                }
                
                const session = this.graphDb.driver.session();
                
                let query;
                if (type) {
                    // Search specific type
                    query = `
                        MATCH (n:${type})
                        WHERE toLower(n.name) CONTAINS toLower($searchTerm)
                           OR toLower(n.title) CONTAINS toLower($searchTerm)
                        RETURN n
                        LIMIT 20
                    `;
                } else {
                    // Search all types
                    query = `
                        MATCH (n)
                        WHERE (n:Group OR n:Person OR n:Release OR n:Track OR n:Song)
                          AND (toLower(n.name) CONTAINS toLower($searchTerm)
                           OR toLower(n.title) CONTAINS toLower($searchTerm))
                        RETURN n
                        LIMIT 20
                    `;
                }
                
                const result = await session.run(query, { searchTerm: q });
                await session.close();
                
                const results = result.records.map(record => {
                    const node = record.get('n');
                    return {
                        id: node.identity.toString(),
                        type: node.labels[0],
                        name: node.properties.name || node.properties.title,
                        properties: node.properties
                    };
                });
                
                res.json(results);
                
            } catch (error) {
                console.error('Search error:', error);
                res.status(500).json({ error: error.message });
            }
        });
        
        // === Events ===
        
        /**
         * Create and store events
         */
        this.app.post('/api/events/create', async (req, res) => {
            try {
                const { type, body, author } = req.body;
                
                // Create canonical event
                const { event, canonical, hash } = await this.eventStore.createEvent(
                    type, body, author
                );
                
                // Store in multiple locations
                const storage = await this.eventStore.storeEvent(event, hash);
                
                res.json({ success: true, hash, storage });
                
            } catch (error) {
                console.error('Event creation error:', error);
                res.status(500).json({ error: error.message });
            }
        });
        
        // === Health Check ===
        
        /**
         * System health check
         */
        this.app.get('/api/health', async (req, res) => {
            try {
                const health = {
                    api: 'healthy',
                    storage: await this.eventStore.healthCheck(),
                    database: await this.checkDatabaseHealth(),
                    redis: await this.checkRedisHealth()
                };
                
                const overallHealth = health.storage.overall && 
                                     health.database && 
                                     health.redis;
                
                res.status(overallHealth ? 200 : 503).json(health);
                
            } catch (error) {
                res.status(503).json({ error: 'Health check failed' });
            }
        });
    }
    
    /**
     * Create GraphQL resolvers
     */
    createResolvers() {
        return {
            // Group resolvers
            group: async ({ id }) => {
                return await this.getGroup(id);
            },
            
            groups: async ({ limit = 10, active }) => {
                return await this.getGroups(limit, active);
            },
            
            groupParticipation: async ({ groupId }) => {
                const participation = await this.graphDb.calculateGroupMemberParticipation(groupId);
                return {
                    groupId,
                    members: participation,
                    totalMembers: participation.length,
                    totalTracks: participation[0]?.totalTracks || 0
                };
            },
            
            // Person resolvers
            person: async ({ id }) => {
                return await this.getPerson(id);
            },
            
            // Release resolvers
            release: async ({ id }) => {
                return await this.getRelease(id);
            },
            
            recentReleases: async ({ limit = 10 }) => {
                return await this.getRecentReleases(limit);
            },
            
            // Search resolver
            search: async ({ query, type }) => {
                return await this.search(query, type);
            },
            
            // Mutations
            createEvent: async ({ type, body }, context) => {
                try {
                    const { event, hash } = await this.eventStore.createEvent(
                        type, body, context.author
                    );
                    await this.eventStore.storeEvent(event, hash);
                    return { success: true, hash };
                } catch (error) {
                    return { success: false, error: error.message };
                }
            },
            
            vote: async ({ targetHash, verdict }, context) => {
                // Implementation for voting
                return { success: true };
            },
            
            stake: async ({ nodeId, amount }, context) => {
                // Implementation for staking
                return { success: true, newTotal: amount };
            }
        };
    }
    
    /**
     * Helper: Get group by ID
     */
    async getGroup(groupId) {
        const session = this.graphDb.driver.session();
        try {
            const result = await session.run(`
                MATCH (g:Group {group_id: $groupId})
                RETURN g
            `, { groupId });
            
            if (result.records.length === 0) return null;
            
            const group = result.records[0].get('g');
            return {
                id: group.properties.group_id,
                name: group.properties.name,
                ...group.properties
            };
        } finally {
            await session.close();
        }
    }
    
    /**
     * Check database health
     */
    async checkDatabaseHealth() {
        try {
            const session = this.graphDb.driver.session();
            await session.run('RETURN 1');
            await session.close();
            return true;
        } catch (error) {
            console.error('Database health check failed:', error);
            return false;
        }
    }
    
    /**
     * Check Redis health
     */
    async checkRedisHealth() {
        try {
            await this.redis.ping();
            return true;
        } catch (error) {
            console.error('Redis health check failed:', error);
            return false;
        }
    }
    
    /**
     * Start the server
     */
    start() {
        this.app.listen(this.port, () => {
            console.log(`API Server running on port ${this.port}`);
            console.log(`GraphQL playground: http://localhost:${this.port}/graphql`);
        });
    }
}

// Start the server
const config = {
    port: process.env.PORT || 3000,
    storage: {
        ipfsUrl: process.env.IPFS_URL || 'http://localhost:5001',
        aws: {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
            region: process.env.AWS_REGION || 'us-east-1',
            bucket: process.env.S3_BUCKET || 'polaris-events'
        },
        redis: {
            host: process.env.REDIS_HOST || 'localhost',
            port: process.env.REDIS_PORT || 6379,
            password: process.env.REDIS_PASSWORD
        }
    },
    neo4j: {
        uri: process.env.NEO4J_URI || 'bolt://localhost:7687',
        user: process.env.NEO4J_USER || 'neo4j',
        password: process.env.NEO4J_PASSWORD
    },
    redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD
    }
};

const server = new APIServer(config);
server.start();

export default APIServer;
```

## Testing Endpoints

```bash
# Test GraphQL
curl -X POST http://localhost:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ groups(limit: 5) { id name memberCount } }"}'

# Test Group Participation
curl http://localhost:3000/api/groups/group:beatles/participation

# Test Search
curl "http://localhost:3000/api/search?q=beatles&type=Group"

# Test Health Check
curl http://localhost:3000/api/health
```