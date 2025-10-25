# Data Import Tools - Migration and Import Utilities

## Overview
Tools for importing data from external sources like Discogs, MusicBrainz, and CSV files into the Polaris music registry.

## Discogs Importer

```javascript
// File: tools/import/discogsImporter.js
// Import releases and artists from Discogs database

import axios from 'axios';
import { EventStore } from '../../src/storage/eventStore.js';
import MusicGraphDatabase from '../../src/graph/schema.js';
import { createHash } from 'crypto';

class DiscogsImporter {
    constructor(config) {
        /**
         * Initialize Discogs importer
         * Requires Discogs API token for rate limits
         */
        
        this.apiBase = 'https://api.discogs.com';
        this.token = config.discogsToken;
        this.userAgent = config.userAgent || 'PolarisImporter/1.0';
        
        this.eventStore = new EventStore(config.storage);
        this.graphDb = new MusicGraphDatabase(config.neo4j);
        
        // Rate limiting (Discogs allows 60 requests per minute)
        this.requestsPerMinute = 60;
        this.requestQueue = [];
        this.lastRequestTime = 0;
    }
    
    /**
     * Import a release from Discogs by ID
     * Converts Discogs format to Polaris format
     * 
     * @param {number} releaseId - Discogs release ID
     * @param {string} submitter - Account importing the data
     */
    async importRelease(releaseId, submitter = 'importer') {
        console.log(`Importing Discogs release ${releaseId}...`);
        
        // Fetch release data from Discogs
        const releaseData = await this.fetchDiscogsRelease(releaseId);
        
        // Convert to Polaris format
        const bundle = await this.convertReleaseToBundle(releaseData);
        
        // Create canonical event
        const { event, hash } = await this.eventStore.createEvent(
            'CREATE_RELEASE_BUNDLE',
            bundle,
            `PUB_K1_${submitter}`
        );
        
        // Store event
        await this.eventStore.storeEvent(event, hash);
        
        // Process into graph
        await this.graphDb.processReleaseBundle(hash, bundle, submitter);
        
        console.log(`Imported release: ${releaseData.title} (${releaseId})`);
        
        return { success: true, releaseId, hash };
    }
    
    /**
     * Fetch release data from Discogs API
     * Handles rate limiting
     * 
     * @param {number} releaseId - Discogs release ID
     */
    async fetchDiscogsRelease(releaseId) {
        // Rate limiting
        await this.rateLimit();
        
        const response = await axios.get(
            `${this.apiBase}/releases/${releaseId}`,
            {
                headers: {
                    'Authorization': `Discogs token=${this.token}`,
                    'User-Agent': this.userAgent
                }
            }
        );
        
        return response.data;
    }
    
    /**
     * Convert Discogs release to Polaris bundle format
     * Maps Discogs fields to Polaris schema
     * 
     * @param {object} discogsRelease - Discogs release data
     */
    async convertReleaseToBundle(discogsRelease) {
        const bundle = {
            release: {
                release_id: `discogs:release/${discogsRelease.id}`,
                name: discogsRelease.title,
                release_date: discogsRelease.released || discogsRelease.year,
                format: discogsRelease.formats ? 
                    discogsRelease.formats.map(f => f.name) : [],
                country: discogsRelease.country,
                catalog_number: discogsRelease.labels ? 
                    discogsRelease.labels[0]?.catno : null,
                notes: discogsRelease.notes,
                master_id: discogsRelease.master_id ? 
                    `discogs:master/${discogsRelease.master_id}` : null,
                label_id: discogsRelease.labels && discogsRelease.labels[0] ? 
                    `discogs:label/${discogsRelease.labels[0].id}` : null,
                label_name: discogsRelease.labels ? 
                    discogsRelease.labels[0]?.name : null
            },
            groups: [],
            songs: [],
            tracks: [],
            tracklist: [],
            sources: [{
                url: `https://www.discogs.com/release/${discogsRelease.id}`,
                type: 'discogs'
            }]
        };
        
        // Process artists to identify groups
        const artistGroups = await this.processDiscogsArtists(discogsRelease.artists);
        bundle.groups = artistGroups.groups;
        
        // Process tracklist
        const trackData = await this.processDiscogsTracklist(
            discogsRelease.tracklist,
            discogsRelease.artists,
            discogsRelease.extraartists
        );
        
        bundle.tracks = trackData.tracks;
        bundle.songs = trackData.songs;
        bundle.tracklist = trackData.tracklist;
        
        return bundle;
    }
    
    /**
     * Process Discogs artists to identify groups and members
     * Distinguishes between groups and individual artists
     * 
     * @param {array} artists - Discogs artists array
     */
    async processDiscogsArtists(artists) {
        const groups = [];
        const individuals = [];
        
        for (const artist of artists || []) {
            // Check if this is a group (band, orchestra, etc.)
            const isGroup = await this.isGroupArtist(artist);
            
            if (isGroup) {
                const group = {
                    group_id: `discogs:artist/${artist.id}`,
                    name: artist.name.replace(/\s*\(\d+\)$/, ''), // Remove numbering
                    members: []
                };
                
                // Fetch group members if available
                if (artist.id) {
                    const members = await this.fetchGroupMembers(artist.id);
                    group.members = members;
                }
                
                groups.push(group);
            } else {
                individuals.push({
                    person_id: `discogs:artist/${artist.id}`,
                    name: artist.name.replace(/\s*\(\d+\)$/, '')
                });
            }
        }
        
        return { groups, individuals };
    }
    
    /**
     * Determine if a Discogs artist is a group
     * Uses various heuristics and API data
     * 
     * @param {object} artist - Discogs artist
     */
    async isGroupArtist(artist) {
        // Quick heuristics
        const groupKeywords = [
            'band', 'orchestra', 'ensemble', 'quartet', 'trio',
            'quintet', 'the ', 'group', 'collective'
        ];
        
        const nameLower = artist.name.toLowerCase();
        if (groupKeywords.some(keyword => nameLower.includes(keyword))) {
            return true;
        }
        
        // Check if name contains "And" or "&" (often indicates group)
        if (nameLower.includes(' and ') || nameLower.includes(' & ')) {
            return true;
        }
        
        // Fetch detailed artist info if ID available
        if (artist.id) {
            try {
                await this.rateLimit();
                const response = await axios.get(
                    `${this.apiBase}/artists/${artist.id}`,
                    {
                        headers: {
                            'Authorization': `Discogs token=${this.token}`,
                            'User-Agent': this.userAgent
                        }
                    }
                );
                
                // Check if artist has members
                if (response.data.members && response.data.members.length > 0) {
                    return true;
                }
                
                // Check if listed as group in profile
                if (response.data.profile) {
                    const profile = response.data.profile.toLowerCase();
                    if (profile.includes('band') || profile.includes('group')) {
                        return true;
                    }
                }
                
            } catch (error) {
                console.error(`Error fetching artist ${artist.id}:`, error);
            }
        }
        
        return false;
    }
    
    /**
     * Fetch group members from Discogs
     * 
     * @param {number} artistId - Discogs artist ID
     */
    async fetchGroupMembers(artistId) {
        const members = [];
        
        try {
            await this.rateLimit();
            const response = await axios.get(
                `${this.apiBase}/artists/${artistId}`,
                {
                    headers: {
                        'Authorization': `Discogs token=${this.token}`,
                        'User-Agent': this.userAgent
                    }
                }
            );
            
            if (response.data.members) {
                for (const member of response.data.members) {
                    members.push({
                        person_id: `discogs:artist/${member.id}`,
                        name: member.name,
                        role: 'member',
                        active: member.active
                    });
                }
            }
            
        } catch (error) {
            console.error(`Error fetching members for artist ${artistId}:`, error);
        }
        
        return members;
    }
    
    /**
     * Process Discogs tracklist to Polaris format
     * Handles track credits and guest appearances
     * 
     * @param {array} tracklist - Discogs tracklist
     * @param {array} artists - Main artists
     * @param {array} extraartists - Additional credits
     */
    async processDiscogsTracklist(tracklist, artists, extraartists) {
        const tracks = [];
        const songs = [];
        const tracklistMapping = [];
        const processedSongs = new Set();
        
        // Determine main performing group
        const mainGroup = artists && artists.length > 0 ? 
            await this.getPrimaryGroup(artists) : null;
        
        for (const discogsTrack of tracklist || []) {
            // Skip headings and index tracks
            if (discogsTrack.type_ !== 'track') {
                continue;
            }
            
            // Generate track ID
            const trackId = this.generateTrackId(discogsTrack);
            
            // Create track
            const track = {
                track_id: trackId,
                title: discogsTrack.title,
                duration: this.parseDuration(discogsTrack.duration),
                position: discogsTrack.position
            };
            
            // Set performing group
            if (mainGroup) {
                track.performed_by_group = mainGroup;
            }
            
            // Process track-specific artists (features, guests)
            if (discogsTrack.artists) {
                track.guests = await this.processTrackGuests(
                    discogsTrack.artists,
                    mainGroup
                );
            }
            
            // Process extra artists (producers, engineers, etc.)
            if (discogsTrack.extraartists) {
                track.additional_credits = this.processExtraArtists(
                    discogsTrack.extraartists
                );
            }
            
            tracks.push(track);
            
            // Create song if not already processed
            const songId = this.generateSongId(discogsTrack);
            if (!processedSongs.has(songId)) {
                songs.push({
                    song_id: songId,
                    title: discogsTrack.title,
                    writers: [] // Discogs doesn't always have songwriter data
                });
                processedSongs.add(songId);
            }
            
            // Map track to tracklist position
            const position = this.parsePosition(discogsTrack.position);
            tracklistMapping.push({
                track_id: trackId,
                disc: position.disc,
                track_number: position.track,
                side: position.side
            });
        }
        
        return {
            tracks,
            songs,
            tracklist: tracklistMapping
        };
    }
    
    /**
     * Get primary performing group from artists
     * 
     * @param {array} artists - Discogs artists
     */
    async getPrimaryGroup(artists) {
        for (const artist of artists) {
            if (await this.isGroupArtist(artist)) {
                return {
                    group_id: `discogs:artist/${artist.id}`,
                    name: artist.name.replace(/\s*\(\d+\)$/, '')
                };
            }
        }
        return null;
    }
    
    /**
     * Process track guests (featuring artists)
     * Distinguishes guests from main group members
     * 
     * @param {array} trackArtists - Artists on specific track
     * @param {object} mainGroup - Main performing group
     */
    async processTrackGuests(trackArtists, mainGroup) {
        const guests = [];
        
        for (const artist of trackArtists) {
            // Skip if this is the main group
            if (mainGroup && artist.id === mainGroup.group_id.split('/')[1]) {
                continue;
            }
            
            // Check if individual artist (not a group)
            if (!await this.isGroupArtist(artist)) {
                guests.push({
                    person_id: `discogs:artist/${artist.id}`,
                    name: artist.name.replace(/\s*\(\d+\)$/, ''),
                    role: 'featuring',
                    credited_as: artist.anv || artist.name // Use alias if available
                });
            }
        }
        
        return guests;
    }
    
    /**
     * Parse duration string to seconds
     * 
     * @param {string} duration - Duration string (e.g., "3:45")
     */
    parseDuration(duration) {
        if (!duration) return null;
        
        const parts = duration.split(':');
        if (parts.length === 2) {
            return parseInt(parts[0]) * 60 + parseInt(parts[1]);
        } else if (parts.length === 3) {
            return parseInt(parts[0]) * 3600 + parseInt(parts[1]) * 60 + parseInt(parts[2]);
        }
        
        return null;
    }
    
    /**
     * Parse track position (e.g., "A1", "2-3")
     * 
     * @param {string} position - Position string
     */
    parsePosition(position) {
        if (!position) {
            return { disc: 1, track: 1 };
        }
        
        // Handle vinyl side notation (A1, B2, etc.)
        const vinylMatch = position.match(/^([A-Z])(\d+)$/);
        if (vinylMatch) {
            return {
                disc: 1,
                track: parseInt(vinylMatch[2]),
                side: vinylMatch[1]
            };
        }
        
        // Handle multi-disc notation (2-3 = disc 2, track 3)
        const discMatch = position.match(/^(\d+)-(\d+)$/);
        if (discMatch) {
            return {
                disc: parseInt(discMatch[1]),
                track: parseInt(discMatch[2])
            };
        }
        
        // Simple track number
        const trackMatch = position.match(/^(\d+)$/);
        if (trackMatch) {
            return {
                disc: 1,
                track: parseInt(trackMatch[1])
            };
        }
        
        return { disc: 1, track: 1 };
    }
    
    /**
     * Generate track ID from Discogs track
     */
    generateTrackId(track) {
        const normalized = [
            'discogs',
            track.title?.toLowerCase(),
            track.position,
            track.duration
        ].join(':');
        
        return `track:discogs:${createHash('sha256')
            .update(normalized)
            .digest('hex')
            .substring(0, 16)}`;
    }
    
    /**
     * Generate song ID from track
     */
    generateSongId(track) {
        const normalized = track.title?.toLowerCase() || '';
        return `song:discogs:${createHash('sha256')
            .update(normalized)
            .digest('hex')
            .substring(0, 16)}`;
    }
    
    /**
     * Rate limiting for Discogs API
     */
    async rateLimit() {
        const now = Date.now();
        const timeSinceLastRequest = now - this.lastRequestTime;
        const minInterval = 60000 / this.requestsPerMinute; // ms between requests
        
        if (timeSinceLastRequest < minInterval) {
            await new Promise(resolve => 
                setTimeout(resolve, minInterval - timeSinceLastRequest)
            );
        }
        
        this.lastRequestTime = Date.now();
    }
}

/**
 * Batch import from Discogs
 */
class DiscogsBatchImporter extends DiscogsImporter {
    /**
     * Import multiple releases from a list
     * 
     * @param {array} releaseIds - Array of Discogs release IDs
     * @param {string} submitter - Account importing
     */
    async importReleases(releaseIds, submitter = 'importer') {
        const results = {
            successful: [],
            failed: [],
            total: releaseIds.length
        };
        
        for (const releaseId of releaseIds) {
            try {
                const result = await this.importRelease(releaseId, submitter);
                results.successful.push(result);
                console.log(`✓ Imported ${releaseId}`);
            } catch (error) {
                results.failed.push({ releaseId, error: error.message });
                console.error(`✗ Failed to import ${releaseId}:`, error.message);
            }
            
            // Progress update
            const processed = results.successful.length + results.failed.length;
            console.log(`Progress: ${processed}/${results.total}`);
        }
        
        return results;
    }
    
    /**
     * Import all releases from a label
     * 
     * @param {number} labelId - Discogs label ID
     * @param {object} options - Import options
     */
    async importLabel(labelId, options = {}) {
        console.log(`Importing releases from label ${labelId}...`);
        
        const limit = options.limit || 100;
        const page = 1;
        const releases = [];
        
        // Fetch label releases
        await this.rateLimit();
        const response = await axios.get(
            `${this.apiBase}/labels/${labelId}/releases`,
            {
                params: { page, per_page: limit },
                headers: {
                    'Authorization': `Discogs token=${this.token}`,
                    'User-Agent': this.userAgent
                }
            }
        );
        
        // Extract release IDs
        const releaseIds = response.data.releases
            .filter(r => r.type === 'release')
            .map(r => r.id);
        
        // Import all releases
        return await this.importReleases(releaseIds, options.submitter);
    }
}

export { DiscogsImporter, DiscogsBatchImporter };
```

## CSV Importer

```javascript
// File: tools/import/csvImporter.js
// Import data from CSV files

import fs from 'fs';
import csv from 'csv-parser';
import { EventStore } from '../../src/storage/eventStore.js';
import MusicGraphDatabase from '../../src/graph/schema.js';

class CSVImporter {
    constructor(config) {
        this.eventStore = new EventStore(config.storage);
        this.graphDb = new MusicGraphDatabase(config.neo4j);
    }
    
    /**
     * Import releases from CSV file
     * Expected columns: name, artist, release_date, label, format
     * 
     * @param {string} filePath - Path to CSV file
     * @param {string} submitter - Account importing
     */
    async importReleasesCSV(filePath, submitter = 'csv-importer') {
        const releases = [];
        
        return new Promise((resolve, reject) => {
            fs.createReadStream(filePath)
                .pipe(csv())
                .on('data', (row) => {
                    releases.push(this.parseReleaseRow(row));
                })
                .on('end', async () => {
                    console.log(`Parsed ${releases.length} releases from CSV`);
                    
                    // Process each release
                    const results = [];
                    for (const release of releases) {
                        try {
                            const result = await this.importRelease(release, submitter);
                            results.push(result);
                        } catch (error) {
                            console.error(`Failed to import release:`, error);
                        }
                    }
                    
                    resolve(results);
                })
                .on('error', reject);
        });
    }
    
    /**
     * Parse CSV row to release format
     * 
     * @param {object} row - CSV row data
     */
    parseReleaseRow(row) {
        // Determine if artist is a group
        const artistName = row.artist || row.Artist || '';
        const isGroup = this.isLikelyGroup(artistName);
        
        const release = {
            name: row.name || row.Name || row.title || row.Title,
            release_date: this.parseDate(row.release_date || row.date || row.Date),
            format: this.parseFormat(row.format || row.Format),
            label: row.label || row.Label
        };
        
        if (isGroup) {
            release.group = {
                name: artistName,
                members: this.parseMembers(row.members || row.Members)
            };
        } else {
            release.artist = {
                name: artistName
            };
        }
        
        // Parse tracks if available
        if (row.tracks || row.Tracks) {
            release.tracks = this.parseTracks(row.tracks || row.Tracks);
        }
        
        return release;
    }
    
    /**
     * Determine if artist name is likely a group
     */
    isLikelyGroup(name) {
        const groupIndicators = [
            'band', 'the ', 'orchestra', 'ensemble',
            ' and ', ' & ', 'quartet', 'trio'
        ];
        
        const nameLower = name.toLowerCase();
        return groupIndicators.some(indicator => nameLower.includes(indicator));
    }
    
    /**
     * Parse date string to ISO format
     */
    parseDate(dateStr) {
        if (!dateStr) return null;
        
        // Try various date formats
        const date = new Date(dateStr);
        if (!isNaN(date)) {
            return date.toISOString().split('T')[0];
        }
        
        // Try year only
        if (/^\d{4}$/.test(dateStr)) {
            return `${dateStr}-01-01`;
        }
        
        return null;
    }
    
    /**
     * Parse format string to array
     */
    parseFormat(formatStr) {
        if (!formatStr) return ['Unknown'];
        
        // Split by common delimiters
        return formatStr.split(/[,;|]/).map(f => f.trim());
    }
    
    /**
     * Parse members from string
     */
    parseMembers(membersStr) {
        if (!membersStr) return [];
        
        // Split by common delimiters
        const names = membersStr.split(/[,;|]/).map(n => n.trim());
        
        return names.map(name => {
            // Try to extract role if in parentheses
            const match = name.match(/^(.+?)\s*\((.+?)\)$/);
            if (match) {
                return {
                    name: match[1],
                    role: match[2]
                };
            }
            return { name, role: 'member' };
        });
    }
    
    /**
     * Parse tracks from string
     */
    parseTracks(tracksStr) {
        if (!tracksStr) return [];
        
        // Split by line breaks or semicolons
        const trackLines = tracksStr.split(/[\n;]/).map(t => t.trim());
        
        return trackLines.map((line, index) => {
            // Try to extract track number and title
            const match = line.match(/^(\d+)\.?\s+(.+)$/);
            if (match) {
                return {
                    track_number: parseInt(match[1]),
                    title: match[2]
                };
            }
            return {
                track_number: index + 1,
                title: line
            };
        });
    }
    
    /**
     * Import a parsed release
     */
    async importRelease(releaseData, submitter) {
        const bundle = {
            release: {
                name: releaseData.name,
                release_date: releaseData.release_date,
                format: releaseData.format
            },
            groups: [],
            tracks: [],
            tracklist: []
        };
        
        // Add group if present
        if (releaseData.group) {
            bundle.groups.push({
                name: releaseData.group.name,
                members: releaseData.group.members
            });
            
            // Set group as performer for tracks
            const groupId = `csv:group:${releaseData.group.name.toLowerCase().replace(/\s+/g, '-')}`;
            
            // Add tracks
            for (const track of releaseData.tracks || []) {
                const trackId = `csv:track:${track.title.toLowerCase().replace(/\s+/g, '-')}`;
                
                bundle.tracks.push({
                    track_id: trackId,
                    title: track.title,
                    performed_by_group: {
                        group_id: groupId,
                        name: releaseData.group.name
                    }
                });
                
                bundle.tracklist.push({
                    track_id: trackId,
                    disc: 1,
                    track_number: track.track_number
                });
            }
        }
        
        // Create and store event
        const { event, hash } = await this.eventStore.createEvent(
            'CREATE_RELEASE_BUNDLE',
            bundle,
            `PUB_K1_${submitter}`
        );
        
        await this.eventStore.storeEvent(event, hash);
        await this.graphDb.processReleaseBundle(hash, bundle, submitter);
        
        return { success: true, release: releaseData.name, hash };
    }
}

export default CSVImporter;
```

## Migration Tools

```javascript
// File: tools/migration/migrate.js
// Database migration tools

import neo4j from 'neo4j-driver';
import { createHash } from 'crypto';

class MigrationTool {
    constructor(config) {
        this.driver = neo4j.driver(
            config.uri,
            neo4j.auth.basic(config.user, config.password)
        );
    }
    
    /**
     * Migrate from old schema to new schema
     * Adds Groups as separate entities
     */
    async migrateToGroupSchema() {
        const session = this.driver.session();
        const tx = session.beginTransaction();
        
        try {
            console.log('Starting migration to Group schema...');
            
            // Step 1: Identify existing artist nodes that are groups
            const groupsResult = await tx.run(`
                MATCH (a:Artist)
                WHERE a.type = 'group' 
                   OR a.name CONTAINS 'Band'
                   OR a.name CONTAINS 'Orchestra'
                   OR a.members IS NOT NULL
                RETURN a
            `);
            
            console.log(`Found ${groupsResult.records.length} groups to migrate`);
            
            // Step 2: Create Group nodes
            for (const record of groupsResult.records) {
                const artist = record.get('a');
                
                await tx.run(`
                    MATCH (a:Artist {artist_id: $artistId})
                    CREATE (g:Group {
                        group_id: $groupId,
                        name: a.name,
                        formed_date: a.formed_date,
                        bio: a.bio,
                        migrated_from: 'artist'
                    })
                    WITH a, g
                    // Transfer relationships
                    MATCH (a)-[r:PERFORMED]->(t:Track)
                    CREATE (g)-[:PERFORMED_ON]->(t)
                    DELETE r
                `, {
                    artistId: artist.properties.artist_id,
                    groupId: `group:${artist.properties.artist_id}`
                });
            }
            
            // Step 3: Create Person nodes for group members
            await tx.run(`
                MATCH (g:Group)
                WHERE g.migrated_from = 'artist'
                MATCH (a:Artist {artist_id: g.group_id})
                WHERE a.members IS NOT NULL
                UNWIND a.members as member
                CREATE (p:Person {
                    person_id: 'person:' + member.id,
                    name: member.name,
                    status: 'migrated'
                })
                CREATE (p)-[:MEMBER_OF {
                    role: member.role,
                    from_date: member.from_date
                }]->(g)
            `);
            
            // Step 4: Update track relationships
            await tx.run(`
                MATCH (t:Track)<-[:PERFORMED]-(a:Artist)
                WHERE NOT a.type = 'group'
                CREATE (p:Person {
                    person_id: 'person:' + a.artist_id,
                    name: a.name,
                    status: 'migrated'
                })
                CREATE (p)-[:GUEST_ON]->(t)
                DELETE a
            `);
            
            await tx.commit();
            console.log('Migration completed successfully');
            
        } catch (error) {
            await tx.rollback();
            console.error('Migration failed:', error);
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Deduplicate entities
     * Merges duplicate nodes based on similarity
     */
    async deduplicateEntities() {
        const session = this.driver.session();
        
        try {
            // Find potential duplicate groups
            const duplicates = await session.run(`
                MATCH (g1:Group), (g2:Group)
                WHERE g1.group_id < g2.group_id
                  AND apoc.text.levenshteinDistance(
                        toLower(g1.name), 
                        toLower(g2.name)
                      ) < 3
                RETURN g1, g2, 
                       apoc.text.levenshteinDistance(
                           toLower(g1.name), 
                           toLower(g2.name)
                       ) as distance
                ORDER BY distance
            `);
            
            console.log(`Found ${duplicates.records.length} potential duplicates`);
            
            // Review and merge duplicates
            for (const record of duplicates.records) {
                const g1 = record.get('g1');
                const g2 = record.get('g2');
                const distance = record.get('distance');
                
                console.log(`Potential duplicate:`);
                console.log(`  ${g1.properties.name} <-> ${g2.properties.name}`);
                console.log(`  Distance: ${distance}`);
                
                // In production, would require manual review
                // For now, merge if distance is 0 (exact match)
                if (distance === 0) {
                    await this.mergeGroups(
                        g1.properties.group_id,
                        g2.properties.group_id
                    );
                }
            }
            
        } finally {
            await session.close();
        }
    }
    
    /**
     * Merge two groups
     */
    async mergeGroups(sourceId, targetId) {
        const session = this.driver.session();
        const tx = session.beginTransaction();
        
        try {
            // Transfer all relationships
            await tx.run(`
                MATCH (source:Group {group_id: $sourceId})
                MATCH (target:Group {group_id: $targetId})
                
                // Transfer member relationships
                OPTIONAL MATCH (p:Person)-[m:MEMBER_OF]->(source)
                MERGE (p)-[newM:MEMBER_OF]->(target)
                ON CREATE SET newM = m
                DELETE m
                
                // Transfer track performances
                OPTIONAL MATCH (source)-[perf:PERFORMED_ON]->(t:Track)
                MERGE (target)-[newPerf:PERFORMED_ON]->(t)
                ON CREATE SET newPerf = perf
                DELETE perf
                
                // Delete source group
                DELETE source
            `, { sourceId, targetId });
            
            await tx.commit();
            console.log(`Merged ${sourceId} into ${targetId}`);
            
        } catch (error) {
            await tx.rollback();
            throw error;
        } finally {
            await session.close();
        }
    }
    
    /**
     * Clean up orphaned nodes
     */
    async cleanupOrphans() {
        const session = this.driver.session();
        
        try {
            // Remove tracks with no release
            const orphanTracks = await session.run(`
                MATCH (t:Track)
                WHERE NOT (t)-[:IN_RELEASE]->(:Release)
                DELETE t
                RETURN count(t) as deleted
            `);
            
            console.log(`Deleted ${orphanTracks.records[0].get('deleted')} orphan tracks`);
            
            // Remove persons with no relationships
            const orphanPersons = await session.run(`
                MATCH (p:Person)
                WHERE NOT (p)-[]->()
                DELETE p
                RETURN count(p) as deleted
            `);
            
            console.log(`Deleted ${orphanPersons.records[0].get('deleted')} orphan persons`);
            
        } finally {
            await session.close();
        }
    }
    
    async close() {
        await this.driver.close();
    }
}

// CLI script
if (require.main === module) {
    const config = {
        uri: process.env.NEO4J_URI || 'bolt://localhost:7687',
        user: process.env.NEO4J_USER || 'neo4j',
        password: process.env.NEO4J_PASSWORD || 'password'
    };
    
    const tool = new MigrationTool(config);
    
    const command = process.argv[2];
    
    switch (command) {
        case 'migrate':
            tool.migrateToGroupSchema()
                .then(() => tool.close())
                .catch(console.error);
            break;
            
        case 'dedupe':
            tool.deduplicateEntities()
                .then(() => tool.close())
                .catch(console.error);
            break;
            
        case 'cleanup':
            tool.cleanupOrphans()
                .then(() => tool.close())
                .catch(console.error);
            break;
            
        default:
            console.log('Usage: node migrate.js [migrate|dedupe|cleanup]');
            process.exit(1);
    }
}

export default MigrationTool;
```

## Import CLI Tool

```javascript
// File: tools/cli/import-cli.js
// Command-line interface for data import

import { Command } from 'commander';
import { DiscogsImporter, DiscogsBatchImporter } from '../import/discogsImporter.js';
import CSVImporter from '../import/csvImporter.js';
import MigrationTool from '../migration/migrate.js';

const program = new Command();

program
    .name('polaris-import')
    .description('Polaris Music Registry import tool')
    .version('1.0.0');

// Discogs import command
program
    .command('discogs <type>')
    .description('Import from Discogs')
    .option('-i, --id <id>', 'Discogs ID to import')
    .option('-f, --file <file>', 'File with list of IDs')
    .option('-l, --limit <limit>', 'Limit number of imports', '10')
    .option('-t, --token <token>', 'Discogs API token')
    .action(async (type, options) => {
        const config = {
            discogsToken: options.token || process.env.DISCOGS_TOKEN,
            storage: getStorageConfig(),
            neo4j: getNeo4jConfig()
        };
        
        const importer = new DiscogsBatchImporter(config);
        
        switch (type) {
            case 'release':
                if (options.id) {
                    await importer.importRelease(options.id);
                } else if (options.file) {
                    const ids = await readIdsFromFile(options.file);
                    await importer.importReleases(ids);
                }
                break;
                
            case 'label':
                if (options.id) {
                    await importer.importLabel(options.id, {
                        limit: parseInt(options.limit)
                    });
                }
                break;
                
            default:
                console.error('Unknown type:', type);
                process.exit(1);
        }
    });

// CSV import command
program
    .command('csv <file>')
    .description('Import from CSV file')
    .action(async (file) => {
        const config = {
            storage: getStorageConfig(),
            neo4j: getNeo4jConfig()
        };
        
        const importer = new CSVImporter(config);
        const results = await importer.importReleasesCSV(file);
        
        console.log(`Imported ${results.length} releases from CSV`);
    });

// Migration command
program
    .command('migrate')
    .description('Run database migrations')
    .action(async () => {
        const tool = new MigrationTool(getNeo4jConfig());
        await tool.migrateToGroupSchema();
        await tool.close();
    });

// Cleanup command
program
    .command('cleanup')
    .description('Clean up database')
    .action(async () => {
        const tool = new MigrationTool(getNeo4jConfig());
        await tool.deduplicateEntities();
        await tool.cleanupOrphans();
        await tool.close();
    });

// Helper functions
function getStorageConfig() {
    return {
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
    };
}

function getNeo4jConfig() {
    return {
        uri: process.env.NEO4J_URI || 'bolt://localhost:7687',
        user: process.env.NEO4J_USER || 'neo4j',
        password: process.env.NEO4J_PASSWORD
    };
}

async function readIdsFromFile(filePath) {
    const fs = require('fs').promises;
    const content = await fs.readFile(filePath, 'utf8');
    return content.split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
}

program.parse(process.argv);
```

## Usage Examples

```bash
# Import a single Discogs release
node tools/cli/import-cli.js discogs release -i 12345

# Import multiple releases from file
node tools/cli/import-cli.js discogs release -f releases.txt

# Import all releases from a label (max 100)
node tools/cli/import-cli.js discogs label -i 5678 -l 100

# Import from CSV
node tools/cli/import-cli.js csv data/releases.csv

# Run migration to add Groups
node tools/cli/import-cli.js migrate

# Clean up duplicates and orphans
node tools/cli/import-cli.js cleanup
```