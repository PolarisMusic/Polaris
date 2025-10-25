# Polaris Music Registry - Complete Documentation

## Overview

Polaris is a decentralized, graph-based music registry built on blockchain technology. It provides a canonical, auditable registry of music creators, releases, tracks, and compositions with Groups (bands/orchestras) as first-class entities.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Frontend                           │
│         JIT Hypertree + RGraph Visualization         │
│              WharfKit Integration                    │
└─────────────────────────────────────────────────────┘
                          │
┌─────────────────────────────────────────────────────┐
│                    API Layer                         │
│           GraphQL + REST Endpoints                   │
└─────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                    │
┌───────────────┐                  ┌────────────────┐
│   Storage     │                  │   Blockchain   │
│  Neo4j Graph  │                  │  EOS/Vaulta    │
│  IPFS + S3    │                  │  Substreams    │
│    Redis      │                  │                │
└───────────────┘                  └────────────────┘
```

## Quick Start

### Prerequisites

- Node.js 18+
- Docker & Docker Compose
- Neo4j 5.0+
- Redis 7.0+
- IPFS node (optional, can use public gateway)
- EOS/Vaulta account (for blockchain submission)

### Installation

```bash
# Clone the repository
git clone https://github.com/polaris/music-registry.git
cd music-registry

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env.local

# Start services with Docker Compose
docker-compose up -d

# Initialize database
npm run init:db

# Start development server
npm run dev
```

### Basic Configuration

```bash
# .env.local
# Blockchain Configuration
CHAIN_ID=1064487b3cd1a897ce03ae5b6a865651747e2e152090f99c1d19d44e01aea5a4
RPC_URL=https://eos.greymass.com
CONTRACT_ACCOUNT=polaris

# Database Configuration
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your-password

# Storage Configuration
IPFS_URL=http://localhost:5001
S3_ENDPOINT=https://s3.amazonaws.com
S3_ACCESS_KEY=your-access-key
S3_SECRET_KEY=your-secret-key
S3_BUCKET=polaris-events

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
```

## Core Concepts

### Groups vs. Persons

**Groups** are collections of persons (bands, orchestras, ensembles):
- Have members with defined roles and time periods
- Perform on tracks as a unit
- Visualized with RGraph showing member participation

**Persons** are individual musicians:
- Can be members of multiple groups
- Can appear as guests on tracks
- Connected to groups with colored edges

### Key Relationships

| Relationship | From → To | Description |
|-------------|-----------|-------------|
| MEMBER_OF | Person → Group | Group membership with dates and roles |
| PERFORMED_ON | Group → Track | Group performed this track |
| GUEST_ON | Person → Track | Guest appearance (not a member) |
| WROTE | Person → Song | Songwriting credit |
| RECORDING_OF | Track → Song | Track records this composition |

### Event Types

All data modifications are submitted as canonical events:

| Event Type | Code | Description |
|------------|------|-------------|
| CREATE_RELEASE_BUNDLE | 21 | Full release with groups and tracks |
| CREATE_GROUP | 22 | Create new group/band |
| ADD_MEMBER | 23 | Add person to group |
| REMOVE_MEMBER | 24 | Mark member departure |
| ADD_CLAIM | 30 | Add data to entity |
| EDIT_CLAIM | 31 | Modify existing data |
| VOTE | 40 | Vote on submission |
| FINALIZE | 50 | Finalize and distribute rewards |

## API Documentation

### GraphQL Endpoint

```graphql
# Get group with members
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
            fromDate
            toDate
            participationPercentage
        }
    }
}

# Search across all entities
query Search($query: String!) {
    search(query: $query) {
        ... on Group {
            id
            name
            memberCount
        }
        ... on Person {
            id
            name
        }
        ... on Release {
            id
            name
            releaseDate
        }
    }
}
```

### REST Endpoints

#### Groups

```http
GET /api/groups/:groupId/participation
```
Returns member participation data for RGraph visualization:
```json
{
    "groupId": "group:beatles",
    "members": [
        {
            "personId": "person:lennon",
            "personName": "John Lennon",
            "trackCount": 213,
            "participationPercentage": 100.0,
            "releaseCount": 13
        }
    ]
}
```

```http
GET /api/groups/:groupId/details
```
Returns comprehensive group information with timeline.

#### Persons

```http
GET /api/persons/:personId/groups
```
Returns all groups a person has been a member of.

#### Graph Data

```http
GET /api/graph/initial
```
Returns initial graph data for visualization.

#### Events

```http
POST /api/events/create
```
Create and store a new event:
```json
{
    "type": "CREATE_GROUP",
    "body": {
        "group": {
            "name": "New Band",
            "formed_date": "2024-01-01"
        },
        "founding_members": [
            {"name": "Member 1", "role": "vocalist"}
        ]
    },
    "author": "account-name"
}
```

## Blockchain Integration

### Smart Contract Actions

```cpp
// Anchor an event on-chain
ACTION put(
    name author,           // Submitting account
    uint8_t type,         // Event type code
    checksum256 hash,     // Event hash
    optional<checksum256> parent,
    uint32_t ts,
    vector<name> tags
);

// Vote on a submission
ACTION vote(
    name voter,
    checksum256 tx_hash,
    int8_t val           // +1, 0, -1
);

// Stake on a node (Group or Person)
ACTION stake(
    name account,
    checksum256 node_id,
    asset quantity
);
```

### Submission Flow

1. **Create Event**: Generate canonical JSON event with deterministic hash
2. **Store Off-chain**: Save to IPFS and S3 (minimum 2 locations)
3. **Anchor On-chain**: Submit hash to blockchain
4. **Process**: Event processor updates graph database
5. **Vote**: Community votes during window (7 days for releases)
6. **Finalize**: Calculate rewards using logarithmic emission

### Emission Formula

```
g(x) = m * ln(x) / x

where:
- x = global submission counter
- m = multiplier by event type
  - CREATE_RELEASE_BUNDLE: 1,000,000
  - CREATE_GROUP: 500,000
  - ADD_MEMBER: 100,000
```

## Frontend Visualization

### Group Nodes with RGraph

Groups display an RGraph showing member participation:
- Each member gets a wedge sized by participation percentage
- Colors are consistent across the visualization
- Percentage labels show contribution levels

```javascript
// Initialize visualization
const visualizer = new MusicGraphVisualizer(
    'graph-container',
    'http://localhost:3000/api'
);
```

### Person to Group Connections

Persons connect to Groups with colored edges:
- Each person-group relationship has a unique color
- Colors are deterministic (same person-group always same color)
- No RGraph around Person nodes

## Data Import

### From Discogs

```bash
# Import single release
node tools/cli/import-cli.js discogs release -i 12345

# Import from label
node tools/cli/import-cli.js discogs label -i 5678 -l 100
```

### From CSV

```bash
# Import from CSV file
node tools/cli/import-cli.js csv data/releases.csv
```

CSV Format:
```csv
name,artist,release_date,format,members
"Abbey Road","The Beatles",1969-09-26,"LP,CD","John Lennon,Paul McCartney,George Harrison,Ringo Starr"
```

## Development

### Running Tests

```bash
# All tests
npm test

# Specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e
npm run test:performance

# With coverage
npm run test:coverage
```

### Project Structure

```
polaris-music-registry/
├── contracts/           # Smart contracts
│   └── polaris.music.cpp
├── backend/
│   ├── src/
│   │   ├── api/        # API server
│   │   ├── graph/      # Graph database
│   │   ├── storage/    # Event storage
│   │   └── indexer/    # Event processor
│   └── test/
├── frontend/
│   ├── src/
│   │   └── visualization/  # JIT graphs
│   └── public/
├── substreams/         # Blockchain indexing
│   ├── src/
│   └── proto/
├── tools/              # Import and migration
│   ├── import/
│   └── migration/
└── docker-compose.yml
```

### Database Schema

#### Nodes
- **Person**: Individual musicians
- **Group**: Bands, orchestras, ensembles
- **Song**: Musical compositions
- **Track**: Recordings of songs
- **Release**: Albums, EPs, singles
- **Master**: Canonical album grouping
- **Label**: Record labels
- **Account**: Blockchain accounts
- **City**: Geographic locations

#### Key Relationships
- `(Person)-[:MEMBER_OF]->(Group)`
- `(Group)-[:PERFORMED_ON]->(Track)`
- `(Person)-[:GUEST_ON]->(Track)`
- `(Track)-[:RECORDING_OF]->(Song)`
- `(Track)-[:IN_RELEASE]->(Release)`

## Deployment

### Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api-server

# Stop services
docker-compose down
```

### Production Deployment

```bash
# Build and deploy
./deploy.sh production v1.0.0

# Run database migrations
kubectl exec -it polaris-api-0 -- npm run migrate

# Scale API servers
kubectl scale deployment polaris-api --replicas=5
```

### Monitoring

Access monitoring dashboards:
- Grafana: http://localhost:3002 (admin/polarisgrafana123)
- Neo4j Browser: http://localhost:7474
- IPFS WebUI: http://localhost:5001/webui

## Troubleshooting

### Common Issues

#### Event Not Processing
```bash
# Check processor logs
docker-compose logs event-processor

# Verify event storage
curl http://localhost:3000/api/events/{hash}

# Check blockchain anchor
cleos get table polaris polaris anchors
```

#### Graph Database Issues
```cypher
// Check database status
CALL dbms.components() YIELD name, versions;

// Clear test data
MATCH (n) WHERE n.status = 'test' DETACH DELETE n;
```

#### Storage Issues
```bash
# Test IPFS
ipfs swarm peers

# Test S3/MinIO
aws s3 ls s3://polaris-events --endpoint-url http://localhost:9000
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

### Code Standards

- Use ESLint configuration
- Write tests for new features
- Document API changes
- Follow commit message conventions

## Security

### Best Practices

1. **Event Validation**: All events are cryptographically signed
2. **Hash Verification**: Content integrity checked on retrieval
3. **Rate Limiting**: API endpoints protected
4. **Input Sanitization**: All user input validated
5. **Access Control**: Smart contract permission checks

### Reporting Issues

Report security issues to: security@polaris.music

## License

MIT License - see LICENSE file for details

## Support

- Documentation: https://docs.polaris.music
- Discord: https://discord.gg/polaris
- GitHub Issues: https://github.com/polaris/music-registry/issues

## Roadmap

### Phase 1: Foundation (Complete)
- ✅ Graph database schema with Groups
- ✅ Smart contract deployment
- ✅ Event storage system
- ✅ Basic visualization

### Phase 2: Enhancement (In Progress)
- 🔄 Fractally integration for Respect voting
- 🔄 Advanced search capabilities
- 🔄 Mobile application
- 🔄 IPNS for mutable references

### Phase 3: Expansion (Planned)
- 📋 Multi-chain support
- 📋 AI-powered deduplication
- 📋 Streaming royalty integration
- 📋 DAO governance

## Acknowledgments

- JIT (JavaScript InfoVis Toolkit) for visualizations
- WharfKit for blockchain integration
- Neo4j for graph database
- IPFS for decentralized storage
- EOS/Vaulta blockchain community