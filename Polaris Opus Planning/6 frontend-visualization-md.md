# Frontend Visualization - JIT Hypertree with Group RGraphs

## Overview
Interactive music graph visualization using JIT (JavaScript InfoVis Toolkit). Groups have RGraph visualizations showing member participation, while Persons have colored edges to their Groups.

## Main Visualization Implementation

```javascript
// File: frontend/src/visualization/MusicGraph.js
// JIT-based interactive music graph with Groups as primary nodes

import $jit from 'jit';
import { Session } from '@wharfkit/session';
import { WalletPluginAnchor } from '@wharfkit/wallet-plugin-anchor';

class MusicGraphVisualizer {
    constructor(containerId, apiEndpoint) {
        /**
         * Initialize the music graph visualization
         * Groups get RGraph, Persons get colored edges
         */
        
        this.container = document.getElementById(containerId);
        this.api = apiEndpoint;
        
        // Color palette for Person->Group connections
        this.memberColors = [
            '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', 
            '#FFEAA7', '#DDA0DD', '#98D8C8', '#F7DC6F',
            '#FF8CC3', '#A8E6CF', '#FFD3B6', '#FFAAA5'
        ];
        
        // Cache for performance
        this.groupParticipationCache = new Map();
        this.nodeDataCache = new Map();
        
        // Initialize WharfKit for blockchain
        this.initializeWharfKit();
        
        // Initialize the main visualization
        this.initializeGraph();
    }
    
    /**
     * Set up WharfKit for blockchain transactions
     * Handles wallet connection and event submission
     */
    async initializeWharfKit() {
        try {
            const response = await Session.login({
                chain: {
                    id: '1064487b3cd1a897ce03ae5b6a865651747e2e152090f99c1d19d44e01aea5a4',
                    url: 'https://eos.greymass.com'
                },
                walletPlugin: new WalletPluginAnchor()
            });
            
            this.session = response.session;
            this.account = response.session.actor;
            
            console.log('Connected to blockchain as:', this.account);
            
        } catch (error) {
            console.error('WharfKit initialization failed:', error);
        }
    }
    
    /**
     * Initialize JIT Hypertree with custom node rendering
     * Main visualization setup with all configurations
     */
    initializeGraph() {
        // Create the main Hypertree visualization
        this.ht = new $jit.Hypertree({
            // Canvas container
            injectInto: this.container.id,
            
            // Canvas dimensions
            width: this.container.offsetWidth,
            height: this.container.offsetHeight,
            
            // Node configuration
            Node: {
                dim: 9,
                color: '#f00',
                overridable: true,
                
                /**
                 * Custom node rendering based on type
                 * Groups get RGraph, others get appropriate visualizations
                 */
                onCreateLabel: (domElement, node) => {
                    // Clear existing content
                    domElement.innerHTML = '';
                    domElement.className = '';
                    
                    // Route to appropriate renderer
                    switch(node.data.type) {
                        case 'Group':
                            this.createGroupNode(domElement, node);
                            break;
                        case 'Person':
                            this.createPersonNode(domElement, node);
                            break;
                        case 'Release':
                            this.createReleaseNode(domElement, node);
                            break;
                        case 'Track':
                            this.createTrackNode(domElement, node);
                            break;
                        case 'Label':
                            this.createLabelNode(domElement, node);
                            break;
                        default:
                            this.createDefaultNode(domElement, node);
                    }
                },
                
                // Node placement handler
                onPlaceLabel: (domElement, node) => {
                    const style = domElement.style;
                    const left = parseInt(style.left);
                    const top = parseInt(style.top);
                    const w = domElement.offsetWidth;
                    const h = domElement.offsetHeight;
                    style.left = (left - w / 2) + 'px';
                    style.top = (top - h / 2) + 'px';
                }
            },
            
            // Edge configuration
            Edge: {
                lineWidth: 2,
                color: '#088',
                overridable: true,
                
                /**
                 * Custom edge rendering for Person->Group connections
                 * Uses unique colors for each person-group relationship
                 */
                onBeforePlotLine: (adj) => {
                    // Special handling for Person->Group edges
                    if (adj.nodeFrom.data.type === 'Person' && 
                        adj.nodeTo.data.type === 'Group') {
                        const colorIndex = this.getPersonGroupColorIndex(
                            adj.nodeFrom.id, 
                            adj.nodeTo.id
                        );
                        adj.data.$color = this.memberColors[colorIndex % this.memberColors.length];
                        adj.data.$lineWidth = 3;
                    }
                    
                    // Special handling for Group->Track edges
                    if (adj.nodeFrom.data.type === 'Group' && 
                        adj.nodeTo.data.type === 'Track') {
                        adj.data.$color = '#2ECC71';
                        adj.data.$lineWidth = 2;
                    }
                }
            },
            
            // Interaction events
            Events: {
                enable: true,
                type: 'HTML',
                
                onClick: (node, eventInfo, e) => {
                    if (!node) return;
                    
                    // Different actions based on node type
                    if (node.data.type === 'Group') {
                        this.onGroupClick(node);
                    } else if (node.data.type === 'Person') {
                        this.onPersonClick(node);
                    } else {
                        this.onNodeClick(node);
                    }
                },
                
                onRightClick: (node, eventInfo, e) => {
                    if (node) {
                        e.preventDefault();
                        this.showNodeMenu(node, e);
                    }
                },
                
                onMouseEnter: (node, eventInfo, e) => {
                    if (node) {
                        this.showNodeTooltip(node, e);
                        if (node.data.type === 'Person') {
                            this.highlightPersonGroups(node.id);
                        }
                    }
                },
                
                onMouseLeave: (node, eventInfo, e) => {
                    this.hideTooltip();
                    this.clearHighlights();
                }
            },
            
            // Animation settings
            duration: 700,
            transition: $jit.Trans.Quart.easeInOut,
            
            // Level distance for hierarchy
            levelDistance: 100,
            
            // Navigation
            Navigation: {
                enable: true,
                panning: true,
                zooming: 20
            },
            
            // Callbacks
            onComplete: () => {
                console.log('Graph rendering complete');
            }
        });
        
        // Load initial data
        this.loadGraphData();
    }
    
    /**
     * Create Group node with RGraph showing member participation
     * This is the key visualization for Groups
     * 
     * @param {HTMLElement} domElement - Container element
     * @param {Object} node - Node data
     */
    createGroupNode(domElement, node) {
        // Main container
        const container = document.createElement('div');
        container.className = 'group-node';
        container.id = `group-${node.id}`;
        container.style.position = 'relative';
        container.style.width = '200px';
        container.style.height = '200px';
        
        // RGraph container for member visualization
        const rgraphDiv = document.createElement('div');
        rgraphDiv.id = `rgraph-${node.id}`;
        rgraphDiv.style.width = '200px';
        rgraphDiv.style.height = '200px';
        container.appendChild(rgraphDiv);
        
        // Group name label in center
        const label = document.createElement('div');
        label.className = 'group-label';
        label.textContent = node.name;
        label.style.position = 'absolute';
        label.style.top = '50%';
        label.style.left = '50%';
        label.style.transform = 'translate(-50%, -50%)';
        label.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
        label.style.color = 'white';
        label.style.padding = '8px';
        label.style.borderRadius = '4px';
        label.style.fontSize = '14px';
        label.style.fontWeight = 'bold';
        label.style.textAlign = 'center';
        label.style.maxWidth = '120px';
        label.style.zIndex = '10';
        container.appendChild(label);
        
        // Member count badge
        if (node.data.memberCount) {
            const badge = document.createElement('div');
            badge.className = 'member-badge';
            badge.textContent = `${node.data.memberCount} members`;
            badge.style.position = 'absolute';
            badge.style.bottom = '5px';
            badge.style.right = '5px';
            badge.style.backgroundColor = '#3498DB';
            badge.style.color = 'white';
            badge.style.padding = '2px 6px';
            badge.style.borderRadius = '10px';
            badge.style.fontSize = '10px';
            container.appendChild(badge);
        }
        
        domElement.appendChild(container);
        
        // Load and render member participation data
        setTimeout(() => {
            this.renderGroupRGraph(rgraphDiv.id, node.id);
        }, 100);
    }
    
    /**
     * Render RGraph showing group member participation
     * Each member gets a wedge proportional to their contribution
     * 
     * @param {string} containerId - RGraph container ID
     * @param {string} groupId - Group identifier
     */
    async renderGroupRGraph(containerId, groupId) {
        // Check cache first
        let participationData = this.groupParticipationCache.get(groupId);
        
        if (!participationData) {
            // Fetch from API
            try {
                const response = await fetch(`${this.api}/groups/${groupId}/participation`);
                participationData = await response.json();
                this.groupParticipationCache.set(groupId, participationData);
            } catch (error) {
                console.error('Failed to load participation data:', error);
                return;
            }
        }
        
        // Create RGraph visualization
        const rgraph = new $jit.RGraph({
            injectInto: containerId,
            width: 200,
            height: 200,
            
            Node: {
                dim: 8,
                color: '#EEE',
                
                onCreateLabel: (domElement, node) => {
                    // Member initials or short name
                    const names = node.name.split(' ');
                    const initials = names.map(n => n[0]).join('');
                    domElement.innerHTML = initials;
                    domElement.style.fontSize = '10px';
                    domElement.style.color = '#333';
                    domElement.style.fontWeight = 'bold';
                }
            },
            
            Edge: {
                color: '#CCC',
                lineWidth: 1
            },
            
            Events: {
                enable: false  // No interaction on the RGraph itself
            },
            
            levelDistance: 50
        });
        
        // Transform participation data to RGraph format
        const graphData = {
            id: groupId,
            name: '',  // Empty center
            data: {
                $type: 'circle',
                $dim: 15,
                $color: '#333'
            },
            children: participationData.members.map((member, index) => ({
                id: member.personId,
                name: member.personName,
                data: {
                    $dim: Math.max(5, Math.sqrt(member.participationPercentage) * 3),
                    $color: this.memberColors[index % this.memberColors.length],
                    $angularWidth: member.participationPercentage * 3.6,  // Convert % to degrees
                    participation: member.participationPercentage,
                    trackCount: member.trackCount,
                    releaseCount: member.releaseCount
                },
                children: []
            }))
        };
        
        // Load and render
        rgraph.loadJSON(graphData);
        rgraph.compute('end');
        rgraph.fx.animate({
            modes: ['polar'],
            duration: 500
        });
        
        // Add percentage labels
        this.addParticipationLabels(containerId, participationData);
    }
    
    /**
     * Add participation percentage labels around the RGraph
     * 
     * @param {string} containerId - Container element ID
     * @param {Object} participationData - Member participation data
     */
    addParticipationLabels(containerId, participationData) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        const centerX = 100;
        const centerY = 100;
        const radius = 80;
        
        participationData.members.forEach((member, index) => {
            // Calculate angle for this member
            const startAngle = participationData.members
                .slice(0, index)
                .reduce((sum, m) => sum + m.participationPercentage * 3.6, 0);
            const midAngle = startAngle + (member.participationPercentage * 3.6 / 2);
            const angleRad = (midAngle - 90) * Math.PI / 180;
            
            // Calculate label position
            const x = centerX + radius * Math.cos(angleRad);
            const y = centerY + radius * Math.sin(angleRad);
            
            // Create percentage label
            const label = document.createElement('div');
            label.className = 'participation-label';
            label.style.position = 'absolute';
            label.style.left = `${x - 20}px`;
            label.style.top = `${y - 10}px`;
            label.style.width = '40px';
            label.style.textAlign = 'center';
            label.style.fontSize = '11px';
            label.style.fontWeight = 'bold';
            label.style.color = this.memberColors[index % this.memberColors.length];
            label.style.backgroundColor = 'rgba(255, 255, 255, 0.9)';
            label.style.borderRadius = '3px';
            label.style.padding = '2px';
            label.textContent = `${Math.round(member.participationPercentage)}%`;
            
            container.appendChild(label);
        });
    }
    
    /**
     * Create Person node (no RGraph, just simple node with colored edges)
     * 
     * @param {HTMLElement} domElement - Container element
     * @param {Object} node - Node data
     */
    createPersonNode(domElement, node) {
        const container = document.createElement('div');
        container.className = 'person-node';
        container.id = `person-${node.id}`;
        container.style.width = '80px';
        container.style.height = '80px';
        container.style.borderRadius = '50%';
        container.style.backgroundColor = '#4A90E2';
        container.style.display = 'flex';
        container.style.alignItems = 'center';
        container.style.justifyContent = 'center';
        container.style.flexDirection = 'column';
        container.style.cursor = 'pointer';
        container.style.border = '3px solid #2C3E50';
        
        // Person icon or photo
        const icon = document.createElement('div');
        if (node.data.photo) {
            const img = document.createElement('img');
            img.src = node.data.photo;
            img.style.width = '50px';
            img.style.height = '50px';
            img.style.borderRadius = '50%';
            icon.appendChild(img);
        } else {
            icon.innerHTML = '👤';
            icon.style.fontSize = '30px';
        }
        container.appendChild(icon);
        
        // Name label
        const label = document.createElement('div');
        label.textContent = node.name;
        label.style.fontSize = '10px';
        label.style.color = 'white';
        label.style.marginTop = '5px';
        label.style.textAlign = 'center';
        label.style.fontWeight = 'bold';
        container.appendChild(label);
        
        domElement.appendChild(container);
    }
    
    /**
     * Create Release node with album art
     * 
     * @param {HTMLElement} domElement - Container element
     * @param {Object} node - Node data
     */
    createReleaseNode(domElement, node) {
        const container = document.createElement('div');
        container.className = 'release-node';
        container.style.width = '120px';
        container.style.height = '140px';
        container.style.border = '2px solid #E74C3C';
        container.style.backgroundColor = 'white';
        container.style.borderRadius = '8px';
        container.style.padding = '5px';
        container.style.cursor = 'pointer';
        
        // Album art
        if (node.data.albumArt) {
            const img = document.createElement('img');
            img.src = node.data.albumArt;
            img.style.width = '100px';
            img.style.height = '100px';
            img.style.display = 'block';
            img.style.margin = '0 auto';
            img.style.borderRadius = '4px';
            container.appendChild(img);
        } else {
            const icon = document.createElement('div');
            icon.innerHTML = '💿';
            icon.style.fontSize = '60px';
            icon.style.textAlign = 'center';
            icon.style.height = '100px';
            icon.style.display = 'flex';
            icon.style.alignItems = 'center';
            icon.style.justifyContent = 'center';
            container.appendChild(icon);
        }
        
        // Release name
        const label = document.createElement('div');
        label.textContent = node.name;
        label.style.fontSize = '11px';
        label.style.textAlign = 'center';
        label.style.marginTop = '5px';
        label.style.overflow = 'hidden';
        label.style.textOverflow = 'ellipsis';
        label.style.whiteSpace = 'nowrap';
        label.style.fontWeight = 'bold';
        container.appendChild(label);
        
        // Release date
        if (node.data.releaseDate) {
            const date = document.createElement('div');
            date.textContent = node.data.releaseDate;
            date.style.fontSize = '9px';
            date.style.textAlign = 'center';
            date.style.color = '#666';
            container.appendChild(date);
        }
        
        domElement.appendChild(container);
    }
    
    /**
     * Create Track node
     * 
     * @param {HTMLElement} domElement - Container element
     * @param {Object} node - Node data
     */
    createTrackNode(domElement, node) {
        const container = document.createElement('div');
        container.className = 'track-node';
        container.style.width = '100px';
        container.style.height = '60px';
        container.style.border = '1px solid #27AE60';
        container.style.backgroundColor = '#E8F8F5';
        container.style.borderRadius = '4px';
        container.style.padding = '5px';
        container.style.cursor = 'pointer';
        
        // Track icon
        const icon = document.createElement('div');
        icon.innerHTML = '🎵';
        icon.style.fontSize = '20px';
        icon.style.float = 'left';
        icon.style.marginRight = '5px';
        container.appendChild(icon);
        
        // Track title
        const title = document.createElement('div');
        title.textContent = node.name;
        title.style.fontSize = '11px';
        title.style.fontWeight = 'bold';
        title.style.overflow = 'hidden';
        title.style.textOverflow = 'ellipsis';
        title.style.whiteSpace = 'nowrap';
        container.appendChild(title);
        
        // Duration
        if (node.data.duration) {
            const duration = document.createElement('div');
            duration.textContent = this.formatDuration(node.data.duration);
            duration.style.fontSize = '9px';
            duration.style.color = '#666';
            container.appendChild(duration);
        }
        
        domElement.appendChild(container);
    }
    
    /**
     * Load graph data from API
     */
    async loadGraphData() {
        try {
            const response = await fetch(`${this.api}/graph/initial`);
            const data = await response.json();
            
            // Transform data to JIT format
            const jitData = this.transformToJitFormat(data);
            
            // Load into visualization
            this.ht.loadJSON(jitData);
            this.ht.refresh();
            
            // Center on root node
            if (jitData.id) {
                this.ht.onClick(jitData.id);
            }
            
        } catch (error) {
            console.error('Failed to load graph data:', error);
        }
    }
    
    /**
     * Transform Neo4j data to JIT hierarchical format
     * 
     * @param {Object} neo4jData - Data from Neo4j
     * @returns {Object} JIT-formatted data
     */
    transformToJitFormat(neo4jData) {
        const nodes = new Map();
        const processedRelationships = new Set();
        
        // Process nodes
        for (const record of neo4jData.nodes) {
            const node = {
                id: record.id,
                name: record.properties.name || record.properties.title,
                data: {
                    type: record.labels[0],
                    ...record.properties
                },
                children: []
            };
            nodes.set(node.id, node);
        }
        
        // Process relationships to build hierarchy
        for (const rel of neo4jData.relationships) {
            const parent = nodes.get(rel.start);
            const child = nodes.get(rel.end);
            
            if (parent && child && !processedRelationships.has(`${rel.start}-${rel.end}`)) {
                parent.children.push(child);
                processedRelationships.add(`${rel.start}-${rel.end}`);
            }
        }
        
        // Find root nodes (no incoming edges) or create synthetic root
        const roots = Array.from(nodes.values()).filter(node => {
            return !neo4jData.relationships.some(rel => rel.end === node.id);
        });
        
        if (roots.length === 1) {
            return roots[0];
        } else if (roots.length > 1) {
            return {
                id: 'root',
                name: 'Music Graph',
                data: { type: 'Root' },
                children: roots
            };
        } else {
            // If no clear root, just return first node
            return Array.from(nodes.values())[0];
        }
    }
    
    /**
     * Handle click on Group node
     * 
     * @param {Object} node - Clicked node
     */
    async onGroupClick(node) {
        // Load detailed member information
        const response = await fetch(`${this.api}/groups/${node.id}/details`);
        const details = await response.json();
        
        // Show detailed panel
        this.showGroupDetailsPanel(details);
        
        // Center on group
        this.ht.onClick(node.id, {
            duration: 1000,
            onComplete: () => {
                console.log('Centered on group:', node.name);
            }
        });
    }
    
    /**
     * Show context menu for node actions
     * 
     * @param {Object} node - Node to show menu for
     * @param {Event} event - Mouse event
     */
    showNodeMenu(node, event) {
        // Remove any existing menu
        const existing = document.getElementById('node-context-menu');
        if (existing) {
            document.body.removeChild(existing);
        }
        
        const menu = document.createElement('div');
        menu.id = 'node-context-menu';
        menu.className = 'context-menu';
        menu.style.position = 'fixed';
        menu.style.left = `${event.pageX}px`;
        menu.style.top = `${event.pageY}px`;
        menu.style.backgroundColor = 'white';
        menu.style.border = '1px solid #ccc';
        menu.style.borderRadius = '4px';
        menu.style.padding = '5px 0';
        menu.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
        menu.style.zIndex = '1000';
        
        // Menu items based on node type
        const items = this.getMenuItems(node);
        
        items.forEach(item => {
            const menuItem = document.createElement('div');
            menuItem.className = 'menu-item';
            menuItem.textContent = item.label;
            menuItem.style.padding = '8px 20px';
            menuItem.style.cursor = 'pointer';
            menuItem.onmouseover = () => {
                menuItem.style.backgroundColor = '#f0f0f0';
            };
            menuItem.onmouseout = () => {
                menuItem.style.backgroundColor = 'transparent';
            };
            menuItem.onclick = () => {
                item.action();
                document.body.removeChild(menu);
            };
            menu.appendChild(menuItem);
        });
        
        document.body.appendChild(menu);
        
        // Remove menu on click outside
        setTimeout(() => {
            document.addEventListener('click', function removeMenu() {
                if (document.body.contains(menu)) {
                    document.body.removeChild(menu);
                }
                document.removeEventListener('click', removeMenu);
            });
        }, 0);
    }
    
    /**
     * Get menu items based on node type
     * 
     * @param {Object} node - Node to get menu for
     * @returns {Array} Menu items
     */
    getMenuItems(node) {
        const items = [
            { label: 'View Details', action: () => this.viewDetails(node) },
            { label: 'Add Claim', action: () => this.addClaim(node) },
            { label: 'Vote', action: () => this.vote(node) },
            { label: 'Stake', action: () => this.stake(node) },
            { label: 'Discuss', action: () => this.discuss(node) }
        ];
        
        // Add type-specific items
        if (node.data.type === 'Group') {
            items.push({ label: 'Add Member', action: () => this.addMember(node) });
            items.push({ label: 'View Timeline', action: () => this.viewTimeline(node) });
        } else if (node.data.type === 'Person') {
            items.push({ label: 'View Groups', action: () => this.viewPersonGroups(node) });
        } else if (node.data.type === 'Release') {
            items.push({ label: 'View Tracks', action: () => this.viewReleaseTracks(node) });
        }
        
        return items;
    }
    
    /**
     * Format duration from seconds to MM:SS
     * 
     * @param {number} seconds - Duration in seconds
     * @returns {string} Formatted duration
     */
    formatDuration(seconds) {
        const minutes = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${minutes}:${secs.toString().padStart(2, '0')}`;
    }
    
    /**
     * Get consistent color index for person-group connections
     * 
     * @param {string} personId - Person identifier
     * @param {string} groupId - Group identifier
     * @returns {number} Color index
     */
    getPersonGroupColorIndex(personId, groupId) {
        const hash = `${personId}-${groupId}`;
        let hashCode = 0;
        for (let i = 0; i < hash.length; i++) {
            hashCode = hash.charCodeAt(i) + ((hashCode << 5) - hashCode);
        }
        return Math.abs(hashCode);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    const visualizer = new MusicGraphVisualizer(
        'graph-container',
        'http://localhost:3000/api'
    );
    
    // Export for debugging
    window.musicGraph = visualizer;
});

export default MusicGraphVisualizer;
```

## CSS Styles

```css
/* File: frontend/src/styles/music-graph.css */

/* Group nodes with RGraph */
.group-node {
    cursor: pointer;
    transition: transform 0.3s ease;
}

.group-node:hover {
    transform: scale(1.05);
}

.group-node.highlighted {
    box-shadow: 0 0 20px rgba(255, 215, 0, 0.8);
}

.group-label {
    user-select: none;
    pointer-events: none;
}

.member-badge {
    user-select: none;
    pointer-events: none;
}

.participation-label {
    pointer-events: none;
    user-select: none;
}

/* Person nodes */
.person-node {
    cursor: pointer;
    transition: all 0.3s ease;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
}

.person-node:hover {
    transform: scale(1.15);
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3);
}

/* Release nodes */
.release-node {
    cursor: pointer;
    transition: all 0.3s ease;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
}

.release-node:hover {
    border-color: #C0392B !important;
    box-shadow: 0 2px 8px rgba(231, 76, 60, 0.3);
    transform: translateY(-2px);
}

/* Track nodes */
.track-node {
    cursor: pointer;
    transition: all 0.2s ease;
}

.track-node:hover {
    background-color: #D5F4E6 !important;
    border-color: #239B56 !important;
}

/* Context menu */
.context-menu {
    min-width: 150px;
}

.menu-item {
    transition: background-color 0.2s ease;
}

/* Tooltips */
.node-tooltip {
    position: fixed;
    background: rgba(0, 0, 0, 0.9);
    color: white;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 12px;
    pointer-events: none;
    z-index: 10000;
    max-width: 300px;
}

/* Details panel */
#group-details-panel {
    position: fixed;
    right: 20px;
    top: 20px;
    width: 350px;
    max-height: 80vh;
    overflow-y: auto;
    background: white;
    border: 2px solid #333;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    z-index: 1000;
}

.member-item {
    margin: 10px 0;
    padding: 10px;
    transition: background-color 0.3s ease;
}

.member-item:hover {
    background-color: rgba(0, 0, 0, 0.05);
}

/* Canvas container */
#graph-container {
    width: 100%;
    height: 100vh;
    position: relative;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

/* Loading indicator */
.graph-loading {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    font-size: 24px;
    color: white;
    text-align: center;
}

.graph-loading::after {
    content: '...';
    animation: dots 1.5s infinite;
}

@keyframes dots {
    0%, 20% { content: '.'; }
    40% { content: '..'; }
    60%, 100% { content: '...'; }
}
```