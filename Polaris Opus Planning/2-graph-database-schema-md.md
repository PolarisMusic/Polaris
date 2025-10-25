# Graph Database Schema - Neo4j Implementation

## Overview
Complete Neo4j graph database schema for the music registry. Groups are first-class entities, with clear distinction between group members (MEMBER_OF) and guest performers (GUEST_ON).

## Schema Implementation

```javascript
// File: backend/src/graph/schema.js
// Neo4j graph database schema and operations
// This stores the normalized music data model with Groups as primary entities

import neo4j from 'neo4j-driver';
import { createHash } from 'crypto';

class MusicGraphDatabase {
    constructor(config) {
        // Initialize Neo4j driver with connection pooling
        this.driver = neo4j.driver(
            config.uri,
            neo4j.auth.basic(config.user, config.password),
            {
                maxConnectionPoolSize: 100,
                connectionTimeout: 30000,
                maxTransactionRetryTime: 30000
            }
        );
    }
    
    /**
     * Initialize all constraints and indexes for the database
     * Must be run before any data insertion to ensure integrity
     * Creates unique constraints on IDs and indexes for common queries
     */
    async initializeSchema() {
        const session = this.driver.session();
        
        try {
            // ========== NODE CONSTRAINTS ==========
            // These ensure each entity has a unique identifier
            
            // Person: Individual musician, producer, engineer, etc.
            await session.run(`
                CREATE CONSTRAINT person_id IF NOT EXISTS
                FOR (p:Person) REQUIRE p.person_id IS UNIQUE
            `);
            
            // Group: Band, orchestra, ensemble - collection of Persons
            await session.run(`
                CREATE CONSTRAINT group_id IF NOT EXISTS
                FOR (g:Group) REQUIRE g.group_id IS UNIQUE
            `);
            
            // Song: Composition (the written musical work)
            await session.run(`
                CREATE CONSTRAINT song_id IF NOT EXISTS
                FOR (s:Song) REQUIRE s.song_id IS UNIQUE
            `);
            
            // Track: Recording (specific performance of a song)
            await session.run(`
                CREATE CONSTRAINT track_id IF NOT EXISTS
                FOR (t:Track) REQUIRE t.track_id IS UNIQUE
            `);
            
            // Release: Album, EP, Single, or other package
            await session.run(`
                CREATE CONSTRAINT release_id IF NOT EXISTS
                FOR (r:Release) REQUIRE r.release_id IS UNIQUE
            `);
            
            // Master: Canonical album entity (groups multiple releases)
            await session.run(`
                CREATE CONSTRAINT master_id IF NOT EXISTS
                FOR (m:Master) REQUIRE m.master_id IS UNIQUE
            `);
            
            // Label: Record label / publisher
            await session.run(`
                CREATE CONSTRAINT label_id IF NOT EXISTS
                FOR (l:Label) REQUIRE l.label_id IS UNIQUE
            `);
            
            // Account: Blockchain account that submits data
            await session.run(`
                CREATE CONSTRAINT account_id IF NOT EXISTS
                FOR (a:Account) REQUIRE a.account_id IS UNIQUE
            `);
            
            // City: Geographic location for origin attribution
            await session.run(`
                CREATE CONSTRAINT city_id IF NOT EXISTS
                FOR (c:City) REQUIRE c.city_id IS UNIQUE
            `);
            
            // Claim: Audit trail for all data changes
            await session.run(`
                CREATE CONSTRAINT claim_id IF NOT EXISTS
                FOR (cl:Claim) REQUIRE cl.claim_id IS UNIQUE
            `);
            
            // Source: External data source reference
            await session.run(`
                CREATE CONSTRAINT source_id IF NOT EXISTS
                FOR (src:Source) REQUIRE src.source_id IS UNIQUE
            `);
            
            // ========== INDEXES FOR PERFORMANCE ==========
            
            // Name searches
            await session.run(`
                CREATE INDEX person_name IF NOT EXISTS
                FOR (p:Person) ON (p.name)
            `);
            
            await session.run(`
                CREATE INDEX group_name IF NOT EXISTS
                FOR (g:Group) ON (g.name)
            `);
            
            // Date-based queries
            await session.run(`
                CREATE INDEX release_date IF NOT EXISTS
                FOR (r:Release) ON (r.release_date)
            `);
            
            // Geographic queries
            await session.run(`
                CREATE INDEX city_location IF NOT EXISTS
                FOR (c:City) ON (c.lat, c.lon)
            `);
            
            // Status filtering
            await session.run(`
                CREATE INDEX person_status IF NOT EXISTS
                FOR (p:Person) ON (p.status)
            `);
            
            await session.run(`
                CREATE INDEX group_active IF NOT EXISTS
                FOR (g:Group) ON (g.disbanded_date)
            `);
            
            console.log('Database schema initialized successfully');
            
        } finally {
            await session.close();
        }
    }
    
    /**
     * Process a CREATE_RELEASE_BUNDLE event
     * This is the main entry point for new music data
     * Creates all entities and relationships in a single transaction
     * 
     * @param {string} eventHash - Hash of the canonical event
     * @param {object} bundle - The release bundle data
     * @param {string} submitterAccount - Blockchain account that submitted
     */
    async processReleaseBundle(eventHash, bundle, submitterAccount) {
        const session = this.driver.session();
        const tx = session.beginTransaction();
        
        try {
            // Generate deterministic operation IDs for each sub-operation
            // This ensures idempotency - replaying the same event is safe
            let opIndex = 0;
            const opId = () => {
                const id = createHash('sha256')
                    .update(eventHash + opIndex.toString())
                    .digest('hex');
                opIndex++;
                return id;
            };
            
            // ========== 1. CREATE/UPDATE GROUPS ==========
            // Groups must be created before we can link members and performances
            
            for (const group of bundle.groups || []) {
                const groupOpId = opId();
                const groupId = group.group_id || 
                               this.generateProvisionalId('group', group);
                
                await tx.run(`
                    MERGE (g:Group {group_id: $groupId})
                    SET g.name = $name,
                        g.alt_names = $altNames,
                        g.bio = $bio,
                        g.formed_date = $formed,
                        g.disbanded_date = $disbanded,
                        g.updated_by = $eventHash,
                        g.updated_at = datetime()
                    
                    // Link to submitter Account
                    WITH g
                    MERGE (a:Account {account_id: $account})
                    MERGE (a)-[sub:SUBMITTED {
                        event_hash: $eventHash,
                        timestamp: datetime()
                    }]->(g)
                    
                    // Link to origin City if provided
                    WITH g
                    WHERE $cityId IS NOT NULL
                    MERGE (c:City {city_id: $cityId})
                    ON CREATE SET c.name = $cityName,
                                 c.lat = $cityLat,
                                 c.lon = $cityLon
                    MERGE (g)-[:ORIGIN]->(c)
                    
                    RETURN g
                `, {
                    groupId,
                    name: group.name,
                    altNames: group.alt_names || [],
                    bio: group.bio,
                    formed: group.formed_date,
                    disbanded: group.disbanded_date,
                    eventHash,
                    account: submitterAccount,
                    cityId: group.origin_city?.id,
                    cityName: group.origin_city?.name,
                    cityLat: group.origin_city?.lat,
                    cityLon: group.origin_city?.lon
                });
                
                // Process Group members with their roles and periods
                for (const member of group.members || []) {
                    const personId = member.person_id || 
                                   this.generateProvisionalId('person', member);
                    
                    await tx.run(`
                        MERGE (p:Person {person_id: $personId})
                        ON CREATE SET p.name = $name,
                                     p.status = $status
                        
                        WITH p
                        MATCH (g:Group {group_id: $groupId})
                        
                        // MEMBER_OF relationship with full details
                        MERGE (p)-[m:MEMBER_OF {claim_id: $claimId}]->(g)
                        SET m.role = $role,
                            m.from_date = $from,
                            m.to_date = $to,
                            m.primary_instrument = $instrument
                        
                        RETURN p
                    `, {
                        personId,
                        name: member.name,
                        status: member.person_id ? 'canonical' : 'provisional',
                        groupId,
                        role: member.role || 'member',
                        from: member.from_date,
                        to: member.to_date,
                        instrument: member.primary_instrument,
                        claimId: groupOpId
                    });
                }
                
                // Create audit claim for group creation
                await this.createClaim(tx, groupOpId, 'Group', groupId, 
                                     'created', group, eventHash);
            }
            
            // ========== 2. CREATE RELEASE ==========
            
            const releaseOpId = opId();
            const releaseId = bundle.release.release_id || 
                             this.generateProvisionalId('release', bundle.release);
            
            await tx.run(`
                MERGE (r:Release {release_id: $releaseId})
                SET r.name = $name,
                    r.alt_names = $altNames,
                    r.release_date = $date,
                    r.format = $format,
                    r.country = $country,
                    r.catalog_number = $catalogNumber,
                    r.liner_notes = $linerNotes,
                    r.trivia = $trivia,
                    r.album_art = $albumArt,
                    r.updated_by = $eventHash
                RETURN r
            `, {
                releaseId,
                name: bundle.release.name,
                altNames: bundle.release.alt_names || [],
                date: bundle.release.release_date,
                format: bundle.release.format || [],
                country: bundle.release.country,
                catalogNumber: bundle.release.catalog_number,
                linerNotes: bundle.release.liner_notes,
                trivia: bundle.release.trivia,
                albumArt: bundle.release.album_art,
                eventHash
            });
            
            // ========== 3. PROCESS SONGS (Compositions) ==========
            
            for (const song of bundle.songs || []) {
                const songOpId = opId();
                const songId = song.song_id || 
                              this.generateProvisionalId('song', song);
                
                await tx.run(`
                    MERGE (s:Song {song_id: $songId})
                    SET s.title = $title,
                        s.alt_titles = $altTitles,
                        s.iswc = $iswc,
                        s.year = $year,
                        s.lyrics = $lyrics
                `, {
                    songId,
                    title: song.title,
                    altTitles: song.alt_titles || [],
                    iswc: song.iswc,
                    year: song.year,
                    lyrics: song.lyrics
                });
                
                // Link songwriters (can be Persons or credited to Groups)
                for (const writer of song.writers || []) {
                    if (writer.person_id) {
                        await tx.run(`
                            MERGE (p:Person {person_id: $personId})
                            WITH p
                            MATCH (s:Song {song_id: $songId})
                            MERGE (p)-[w:WROTE {claim_id: $claimId}]->(s)
                            SET w.role = $role,
                                w.share_percentage = $share
                        `, {
                            personId: writer.person_id,
                            songId,
                            role: writer.role || 'writer',
                            share: writer.share_percentage,
                            claimId: songOpId
                        });
                    }
                }
                
                await this.createClaim(tx, songOpId, 'Song', songId,
                                     'created', song, eventHash);
            }
            
            // ========== 4. PROCESS TRACKS (Recordings) ==========
            
            for (const track of bundle.tracks || []) {
                const trackOpId = opId();
                const trackId = track.track_id ||
                               this.generateProvisionalId('track', track);
                
                await tx.run(`
                    MERGE (t:Track {track_id: $trackId})
                    SET t.title = $title,
                        t.isrc = $isrc,
                        t.duration = $duration,
                        t.recording_date = $recordingDate,
                        t.recording_location = $location,
                        t.listen_links = $listenLinks
                `, {
                    trackId,
                    title: track.title,
                    isrc: track.isrc,
                    duration: track.duration,
                    recordingDate: track.recording_date,
                    location: track.recording_location,
                    listenLinks: track.listen_links || []
                });
                
                // ========== CRITICAL: DISTINGUISH GROUPS vs GUESTS ==========
                
                // Link performing GROUP (the main band/orchestra)
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
                        groupName: track.performed_by_group.name || 'Unknown',
                        creditedAs: track.performed_by_group.credited_as,
                        claimId: trackOpId
                    });
                }
                
                // Link GUEST performers (individuals not in the main group)
                for (const guest of track.guests || []) {
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
                            g.credited_as = $creditedAs
                    `, {
                        personId: guest.person_id || 
                                 this.generateProvisionalId('person', guest),
                        name: guest.name,
                        status: guest.person_id ? 'canonical' : 'provisional',
                        trackId,
                        role: guest.role,
                        instrument: guest.instrument,
                        creditedAs: guest.credited_as,
                        claimId: trackOpId
                    });
                }
                
                // Link to Song if it's a recording of a composition
                if (track.recording_of_song_id) {
                    await tx.run(`
                        MATCH (t:Track {track_id: $trackId})
                        MATCH (s:Song {song_id: $songId})
                        MERGE (t)-[r:RECORDING_OF {claim_id: $claimId}]->(s)
                    `, {
                        trackId,
                        songId: track.recording_of_song_id,
                        claimId: trackOpId
                    });
                }
                
                // Link samples
                for (const sample of track.samples || []) {
                    await tx.run(`
                        MATCH (t1:Track {track_id: $trackId})
                        MERGE (t2:Track {track_id: $sampleId})
                        ON CREATE SET t2.status = 'provisional',
                                     t2.title = $sampleTitle
                        MERGE (t1)-[s:SAMPLES {claim_id: $claimId}]->(t2)
                        SET s.portion_used = $portion,
                            s.cleared = $cleared
                    `, {
                        trackId,
                        sampleId: sample.track_id,
                        sampleTitle: sample.title || 'Unknown',
                        portion: sample.portion_used,
                        cleared: sample.cleared,
                        claimId: trackOpId
                    });
                }
                
                // Link cover versions
                if (track.cover_of_song_id) {
                    await tx.run(`
                        MATCH (t:Track {track_id: $trackId})
                        MATCH (s:Song {song_id: $songId})
                        MERGE (t)-[c:COVER_OF {claim_id: $claimId}]->(s)
                    `, {
                        trackId,
                        songId: track.cover_of_song_id,
                        claimId: trackOpId
                    });
                }
                
                await this.createClaim(tx, trackOpId, 'Track', trackId,
                                     'created', track, eventHash);
            }
            
            // ========== 5. CREATE TRACKLIST ==========
            // Link tracks to the release with order information
            
            for (const item of bundle.tracklist || []) {
                await tx.run(`
                    MATCH (t:Track {track_id: $trackId})
                    MATCH (r:Release {release_id: $releaseId})
                    MERGE (t)-[i:IN_RELEASE]->(r)
                    SET i.disc_number = $disc,
                        i.track_number = $trackNo,
                        i.side = $side,
                        i.is_bonus = $isBonus
                `, {
                    trackId: item.track_id,
                    releaseId,
                    disc: item.disc || 1,
                    trackNo: item.track_number,
                    side: item.side,
                    isBonus: item.is_bonus || false
                });
            }
            
            // ========== 6. LINK MASTER AND LABEL ==========
            
            if (bundle.release.master_id) {
                await tx.run(`
                    MERGE (m:Master {master_id: $masterId})
                    ON CREATE SET m.name = $masterName
                    WITH m
                    MATCH (r:Release {release_id: $releaseId})
                    MERGE (r)-[:IN_MASTER]->(m)
                `, {
                    masterId: bundle.release.master_id,
                    masterName: bundle.release.master_name || bundle.release.name,
                    releaseId
                });
            }
            
            if (bundle.release.label_id) {
                await tx.run(`
                    MERGE (l:Label {label_id: $labelId})
                    ON CREATE SET l.name = $labelName
                    
                    WITH l
                    MATCH (r:Release {release_id: $releaseId})
                    MERGE (r)-[:UNDER]->(l)
                `, {
                    labelId: bundle.release.label_id,
                    labelName: bundle.release.label_name,
                    releaseId
                });
            }
            
            // ========== 7. CREATE SOURCE REFERENCES ==========
            
            for (const source of bundle.sources || []) {
                const sourceId = this.generateProvisionalId('source', source);
                
                await tx.run(`
                    MERGE (s:Source {source_id: $sourceId})
                    SET s.url = $url,
                        s.type = $type,
                        s.retrieved_at = $retrievedAt
                    
                    WITH s
                    MATCH (r:Release {release_id: $releaseId})
                    MERGE (r)-[:SOURCED_FROM]->(s)
                `, {
                    sourceId,
                    url: source.url,
                    type: source.type || 'web',
                    retrievedAt: source.retrieved_at || new Date().toISOString(),
                    releaseId
                });
            }
            
            // Commit the entire transaction
            await tx.commit();
            
            console.log(`Processed release bundle ${releaseId} with ${bundle.tracks?.length || 0} tracks`);
            
            return {
                success: true,
                releaseId,
                stats: {
                    groups_created: bundle.groups?.length || 0,
                    songs_created: bundle.songs?.length || 0,
                    tracks_created: bundle.tracks?.length || 0
                }
            };
            
        } catch (error) {
            // Rollback on any error
            await tx.rollback();
            console.error('Failed to process release bundle:', error);
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Process an ADD_CLAIM event to add new information
     * Claims provide an audit trail for all data changes
     * 
     * @param {string} eventHash - Hash of the event
     * @param {object} claimData - The claim details
     * @param {string} author - Account making the claim
     */
    async processAddClaim(eventHash, claimData, author) {
        const session = this.driver.session();
        const tx = session.beginTransaction();
        
        try {
            const claimId = this.generateOpId(eventHash, 0);
            const { node, field, value, source } = claimData;
            
            // Update the target node
            await tx.run(`
                MATCH (n:${node.type} {${node.type.toLowerCase()}_id: $nodeId})
                SET n[$field] = $value,
                    n.last_updated = datetime(),
                    n.last_updated_by = $author
                RETURN n
            `, {
                nodeId: node.id,
                field,
                value,
                author
            });
            
            // Create claim record
            await this.createClaim(tx, claimId, node.type, node.id,
                                 field, value, eventHash);
            
            // Link source if provided
            if (source) {
                const sourceId = this.generateProvisionalId('source', source);
                await tx.run(`
                    MERGE (s:Source {source_id: $sourceId})
                    SET s.url = $url
                    
                    WITH s
                    MATCH (c:Claim {claim_id: $claimId})
                    MERGE (c)-[:SOURCED_FROM]->(s)
                `, {
                    sourceId,
                    url: source.url,
                    claimId
                });
            }
            
            await tx.commit();
            return { success: true, claimId };
            
        } catch (error) {
            await tx.rollback();
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Calculate group member participation percentages
     * Used for the RGraph visualization around Group nodes
     * 
     * @param {string} groupId - Group to analyze
     * @returns {Array} Member participation data
     */
    async calculateGroupMemberParticipation(groupId) {
        const session = this.driver.session();
        
        try {
            const result = await session.run(`
                MATCH (g:Group {group_id: $groupId})
                MATCH (g)-[:PERFORMED_ON]->(t:Track)
                MATCH (t)-[:IN_RELEASE]->(r:Release)
                
                // For each track, find which members were active
                OPTIONAL MATCH (p:Person)-[m:MEMBER_OF]->(g)
                WHERE (m.from_date IS NULL OR date(m.from_date) <= date(r.release_date))
                  AND (m.to_date IS NULL OR date(m.to_date) >= date(r.release_date))
                
                // Count tracks per member
                WITH p, count(DISTINCT t) as track_count, 
                     collect(DISTINCT r.release_id) as releases
                
                // Get total tracks for percentage
                MATCH (g:Group {group_id: $groupId})-[:PERFORMED_ON]->(total:Track)
                WITH p, track_count, releases, count(DISTINCT total) as total_tracks
                
                RETURN p.person_id as personId,
                       p.name as personName,
                       track_count,
                       total_tracks,
                       toFloat(track_count) / toFloat(total_tracks) * 100 as participationPercentage,
                       size(releases) as releaseCount
                ORDER BY participationPercentage DESC
            `, { groupId });
            
            return result.records.map(record => ({
                personId: record.get('personId'),
                personName: record.get('personName'),
                trackCount: record.get('track_count').toNumber(),
                totalTracks: record.get('total_tracks').toNumber(),
                participationPercentage: record.get('participationPercentage'),
                releaseCount: record.get('releaseCount').toNumber()
            }));
            
        } finally {
            await session.close();
        }
    }
    
    /**
     * Find potential duplicates based on similar names
     * Used for deduplication and MERGE_NODE operations
     * 
     * @param {string} type - Entity type to check
     * @param {string} name - Name to match
     */
    async findPotentialDuplicates(type, name) {
        const session = this.driver.session();
        
        try {
            // Use fuzzy matching with Levenshtein distance
            const result = await session.run(`
                MATCH (n:${type})
                WHERE apoc.text.levenshteinDistance(
                    toLower(n.name), 
                    toLower($name)
                ) < 3
                OR ANY(alt IN n.alt_names WHERE 
                    apoc.text.levenshteinDistance(
                        toLower(alt), 
                        toLower($name)
                    ) < 3
                )
                RETURN n.${type.toLowerCase()}_id as id,
                       n.name as name,
                       n.alt_names as altNames,
                       n.status as status
                LIMIT 10
            `, { name });
            
            return result.records.map(record => ({
                id: record.get('id'),
                name: record.get('name'),
                altNames: record.get('altNames'),
                status: record.get('status')
            }));
            
        } finally {
            await session.close();
        }
    }
    
    /**
     * Merge duplicate nodes into canonical entity
     * Preserves all relationships and claims
     * 
     * @param {string} sourceId - Provisional/duplicate node
     * @param {string} targetId - Canonical node to merge into
     * @param {string} reason - Reason for merge
     */
    async mergeNodes(sourceId, targetId, reason) {
        const session = this.driver.session();
        const tx = session.beginTransaction();
        
        try {
            // Get node type
            const typeResult = await tx.run(`
                MATCH (s {id: $sourceId})
                RETURN labels(s)[0] as type
            `, { sourceId });
            
            const nodeType = typeResult.records[0].get('type');
            
            // Merge nodes using APOC
            await tx.run(`
                MATCH (source:${nodeType} {${nodeType.toLowerCase()}_id: $sourceId})
                MATCH (target:${nodeType} {${nodeType.toLowerCase()}_id: $targetId})
                
                // Copy all properties from source to target (if not already set)
                SET target += source
                SET target.status = 'canonical'
                
                // Transfer all relationships
                WITH source, target
                CALL apoc.refactor.mergeNodes([source, target], {
                    properties: 'combine',
                    mergeRels: true
                }) YIELD node
                
                RETURN node
            `, { sourceId, targetId });
            
            // Create merge record for audit
            const mergeId = createHash('sha256')
                .update(sourceId + targetId + Date.now())
                .digest('hex');
                
            await tx.run(`
                CREATE (m:MergeRecord {
                    merge_id: $mergeId,
                    source_id: $sourceId,
                    target_id: $targetId,
                    reason: $reason,
                    merged_at: datetime()
                })
            `, { mergeId, sourceId, targetId, reason });
            
            await tx.commit();
            console.log(`Merged ${sourceId} into ${targetId}`);
            
            return { success: true, mergeId };
            
        } catch (error) {
            await tx.rollback();
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Create audit trail claim for data changes
     * Every modification is tracked with source and timestamp
     * 
     * @param {Transaction} tx - Active Neo4j transaction
     * @param {string} claimId - Unique claim identifier
     * @param {string} nodeType - Type of node being claimed about
     * @param {string} nodeId - ID of the node
     * @param {string} field - Field being modified
     * @param {any} value - New value
     * @param {string} eventHash - Hash of the source event
     */
    async createClaim(tx, claimId, nodeType, nodeId, field, value, eventHash) {
        await tx.run(`
            CREATE (c:Claim {
                claim_id: $claimId,
                node_type: $nodeType,
                node_id: $nodeId,
                field: $field,
                value: $value,
                event_hash: $eventHash,
                created_at: datetime()
            })
        `, {
            claimId,
            nodeType,
            nodeId,
            field,
            value: JSON.stringify(value),
            eventHash
        });
    }
    
    /**
     * Generate deterministic provisional ID when external ID unavailable
     * IDs are consistent for the same input data
     * 
     * @param {string} type - Entity type
     * @param {object} data - Entity data
     */
    generateProvisionalId(type, data) {
        let normalizedString;
        
        switch(type) {
            case 'group':
                // Group ID based on name and founding members
                normalizedString = [
                    data.name?.toLowerCase(),
                    data.formed_date,
                    ...(data.members || []).map(m => m.name).sort()
                ].join('|');
                break;
                
            case 'person':
                // Person ID based on name
                normalizedString = data.name?.toLowerCase() || '';
                break;
                
            case 'track':
                // Track ID based on title, duration, and performers
                normalizedString = [
                    data.title?.toLowerCase(),
                    data.duration,
                    data.performed_by_group?.name
                ].join('|');
                break;
                
            case 'song':
                // Song ID based on title and writers
                normalizedString = [
                    data.title?.toLowerCase(),
                    ...(data.writers || []).map(w => w.person_id || w.name).sort()
                ].join('|');
                break;
                
            case 'release':
                // Release ID based on name, date, and label
                normalizedString = [
                    data.name?.toLowerCase(),
                    data.release_date,
                    data.label_id
                ].join('|');
                break;
                
            case 'source':
                // Source ID based on URL
                normalizedString = data.url;
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
     * Generate operation ID for sub-operations within an event
     * 
     * @param {string} eventHash - Parent event hash
     * @param {number} index - Operation index
     */
    generateOpId(eventHash, index) {
        return createHash('sha256')
            .update(eventHash + index.toString())
            .digest('hex');
    }
    
    /**
     * Clean up and close database connections
     */
    async close() {
        await this.driver.close();
    }
}

export default MusicGraphDatabase;
```

## Node Types Summary

| Node Type | Purpose | Key Properties |
|-----------|---------|----------------|
| Person | Individual musician/artist | person_id, name, bio, status |
| Group | Band/ensemble/orchestra | group_id, name, formed_date, member_count |
| Song | Musical composition | song_id, title, iswc, writers |
| Track | Recording of a song | track_id, title, isrc, duration |
| Release | Album/EP/Single | release_id, name, release_date, format |
| Master | Canonical album grouping | master_id, name |
| Label | Record label | label_id, name |
| Account | Blockchain account | account_id |
| City | Geographic location | city_id, name, lat, lon |
| Claim | Audit trail | claim_id, node_id, field, value |
| Source | External reference | source_id, url |

## Relationship Types Summary

| Relationship | From → To | Purpose |
|--------------|-----------|---------|
| MEMBER_OF | Person → Group | Group membership with dates |
| PERFORMED_ON | Group → Track | Group performed this track |
| GUEST_ON | Person → Track | Guest appearance (not a member) |
| WROTE | Person → Song | Songwriting credit |
| RECORDING_OF | Track → Song | Track records this song |
| COVER_OF | Track → Song | Cover version |
| SAMPLES | Track → Track | Sampling relationship |
| IN_RELEASE | Track → Release | Track appears on release |
| IN_MASTER | Release → Master | Release variant of master |
| UNDER | Release → Label | Released by label |
| ORIGIN | Person/Group → City | Geographic origin |
| SUBMITTED | Account → Any | Who submitted data |

## Testing Queries

```cypher
-- Find all groups and their current members
MATCH (g:Group)
OPTIONAL MATCH (p:Person)-[m:MEMBER_OF]->(g)
WHERE m.to_date IS NULL
RETURN g.name, collect(p.name) as current_members

-- Find tracks where someone was a guest (not a member)
MATCH (p:Person)-[:GUEST_ON]->(t:Track)
MATCH (t)-[:IN_RELEASE]->(r:Release)
RETURN p.name, t.title, r.name

-- Calculate group participation percentages
MATCH (g:Group {name: "The Beatles"})
MATCH (p:Person)-[m:MEMBER_OF]->(g)
MATCH (g)-[:PERFORMED_ON]->(t:Track)
WITH p, count(t) as track_count
MATCH (g:Group {name: "The Beatles"})-[:PERFORMED_ON]->(total:Track)
WITH p, track_count, count(distinct total) as total_tracks
RETURN p.name, toFloat(track_count) / toFloat(total_tracks) * 100 as percentage
```