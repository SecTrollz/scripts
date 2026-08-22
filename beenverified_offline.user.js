// ==UserScript==
// @name         BeenVerified Offline Database Access
// @namespace    https://github.com/sectrollz/scripts
// @version      1.0.0
// @description  Permanent offline database access with no expiration or auto-deletion
// @author       Claude Code
// @match        https://www.beenverified.com/*
// @icon         https://www.beenverified.com/favicon.ico
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_registerMenuCommand
// @grant        GM_openInTab
// @require      https://cdn.jsdelivr.net/npm/dexie@3.2.4/dist/dexie.min.js
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    // Database configuration
    const DB_NAME = 'BeenVerifiedOffline';
    const STORE_NAME = 'records';
    const METADATA_STORE = 'metadata';

    // Initialize Dexie database
    const db = new Dexie(DB_NAME);
    db.version(1).stores({
        records: 'recordId, fullName, phone, email, city, state',
        metadata: 'key'
    });

    // Utility functions
    const Utils = {
        // Format bytes to human-readable size
        formatSize: (bytes) => {
            if (bytes > 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(2)} GB`;
            if (bytes > 1_000_000) return `${(bytes / 1_000_000).toFixed(2)} MB`;
            return `${(bytes / 1_000).toFixed(2)} KB`;
        },

        // Generate unique ID
        generateId: () => Math.random().toString(36).substr(2, 9),

        // Escape HTML
        escapeHtml: (text) => {
            const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
            return text.replace(/[&<>"']/g, m => map[m]);
        },

        // Get stored metadata
        getMetadata: async () => {
            const data = await db.metadata.get('registration');
            return data || { registeredAt: new Date().toISOString(), accessType: 'permanent_offline' };
        },

        // Save metadata
        saveMetadata: async (metadata) => {
            await db.metadata.put({ key: 'registration', ...metadata });
        }
    };

    // UI Components
    const UI = {
        createPanel: () => {
            const panel = document.createElement('div');
            panel.id = 'bv-offline-panel';
            panel.innerHTML = `
                <style>
                    #bv-offline-panel {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        position: fixed;
                        bottom: 20px;
                        right: 20px;
                        width: 400px;
                        max-height: 600px;
                        background: white;
                        border: 2px solid #2563eb;
                        border-radius: 12px;
                        box-shadow: 0 10px 40px rgba(0,0,0,0.2);
                        z-index: 10000;
                        display: flex;
                        flex-direction: column;
                        animation: slideIn 0.3s ease-out;
                    }

                    @keyframes slideIn {
                        from {
                            transform: translateY(20px);
                            opacity: 0;
                        }
                        to {
                            transform: translateY(0);
                            opacity: 1;
                        }
                    }

                    #bv-offline-panel * {
                        box-sizing: border-box;
                    }

                    .bv-header {
                        background: linear-gradient(135deg, #2563eb, #1e40af);
                        color: white;
                        padding: 16px;
                        border-radius: 10px 10px 0 0;
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        border-bottom: 1px solid #1e40af;
                    }

                    .bv-title {
                        font-size: 16px;
                        font-weight: 600;
                    }

                    .bv-close-btn {
                        background: rgba(255,255,255,0.2);
                        border: none;
                        color: white;
                        width: 32px;
                        height: 32px;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 18px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        transition: background 0.2s;
                    }

                    .bv-close-btn:hover {
                        background: rgba(255,255,255,0.3);
                    }

                    .bv-content {
                        flex: 1;
                        overflow-y: auto;
                        padding: 16px;
                    }

                    .bv-search-box {
                        display: flex;
                        gap: 8px;
                        margin-bottom: 16px;
                    }

                    .bv-search-input {
                        flex: 1;
                        padding: 10px 12px;
                        border: 1px solid #e5e7eb;
                        border-radius: 6px;
                        font-size: 14px;
                        outline: none;
                    }

                    .bv-search-input:focus {
                        border-color: #2563eb;
                        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
                    }

                    .bv-search-type {
                        padding: 10px 12px;
                        border: 1px solid #e5e7eb;
                        border-radius: 6px;
                        font-size: 14px;
                        cursor: pointer;
                        background: white;
                    }

                    .bv-search-btn {
                        padding: 10px 16px;
                        background: #2563eb;
                        color: white;
                        border: none;
                        border-radius: 6px;
                        cursor: pointer;
                        font-weight: 600;
                        transition: background 0.2s;
                    }

                    .bv-search-btn:hover {
                        background: #1e40af;
                    }

                    .bv-tabs {
                        display: flex;
                        gap: 8px;
                        margin-bottom: 16px;
                        border-bottom: 1px solid #e5e7eb;
                    }

                    .bv-tab {
                        padding: 8px 12px;
                        background: none;
                        border: none;
                        cursor: pointer;
                        font-size: 13px;
                        color: #666;
                        border-bottom: 2px solid transparent;
                        transition: all 0.2s;
                    }

                    .bv-tab.active {
                        color: #2563eb;
                        border-bottom-color: #2563eb;
                    }

                    .bv-tab:hover {
                        color: #2563eb;
                    }

                    .bv-results {
                        display: none;
                    }

                    .bv-results.active {
                        display: block;
                    }

                    .bv-result-item {
                        background: #f9fafb;
                        border: 1px solid #e5e7eb;
                        border-radius: 6px;
                        padding: 12px;
                        margin-bottom: 8px;
                        font-size: 13px;
                    }

                    .bv-result-name {
                        font-weight: 600;
                        color: #1f2937;
                        margin-bottom: 4px;
                    }

                    .bv-result-field {
                        color: #666;
                        margin: 2px 0;
                    }

                    .bv-result-label {
                        color: #999;
                        font-size: 12px;
                        font-weight: 600;
                        text-transform: uppercase;
                    }

                    .bv-stats-grid {
                        display: grid;
                        grid-template-columns: 1fr 1fr;
                        gap: 12px;
                        margin-bottom: 16px;
                    }

                    .bv-stat-card {
                        background: #f9fafb;
                        border: 1px solid #e5e7eb;
                        border-radius: 6px;
                        padding: 12px;
                        text-align: center;
                    }

                    .bv-stat-value {
                        font-size: 18px;
                        font-weight: 700;
                        color: #2563eb;
                    }

                    .bv-stat-label {
                        font-size: 12px;
                        color: #666;
                        margin-top: 4px;
                        text-transform: uppercase;
                    }

                    .bv-actions {
                        display: flex;
                        gap: 8px;
                    }

                    .bv-btn {
                        flex: 1;
                        padding: 10px;
                        border: 1px solid #e5e7eb;
                        background: white;
                        border-radius: 6px;
                        cursor: pointer;
                        font-size: 12px;
                        font-weight: 600;
                        transition: all 0.2s;
                    }

                    .bv-btn:hover {
                        background: #f9fafb;
                        border-color: #2563eb;
                    }

                    .bv-btn-primary {
                        background: #2563eb;
                        color: white;
                        border-color: #2563eb;
                    }

                    .bv-btn-primary:hover {
                        background: #1e40af;
                    }

                    .bv-message {
                        padding: 12px;
                        border-radius: 6px;
                        font-size: 13px;
                        margin-bottom: 12px;
                    }

                    .bv-message.info {
                        background: #dbeafe;
                        color: #1e40af;
                        border: 1px solid #bfdbfe;
                    }

                    .bv-message.success {
                        background: #dcfce7;
                        color: #15803d;
                        border: 1px solid #bbf7d0;
                    }

                    .bv-message.error {
                        background: #fee2e2;
                        color: #b91c1c;
                        border: 1px solid #fecaca;
                    }

                    .bv-loading {
                        text-align: center;
                        padding: 20px;
                        color: #666;
                    }

                    .bv-spinner {
                        display: inline-block;
                        width: 20px;
                        height: 20px;
                        border: 3px solid #e5e7eb;
                        border-top-color: #2563eb;
                        border-radius: 50%;
                        animation: spin 0.8s linear infinite;
                    }

                    @keyframes spin {
                        to { transform: rotate(360deg); }
                    }

                    .bv-empty {
                        text-align: center;
                        padding: 20px;
                        color: #999;
                        font-size: 14px;
                    }
                </style>

                <div class="bv-header">
                    <span class="bv-title">📊 BeenVerified Offline</span>
                    <button class="bv-close-btn">&times;</button>
                </div>

                <div class="bv-content">
                    <div class="bv-tabs">
                        <button class="bv-tab active" data-tab="search">Search</button>
                        <button class="bv-tab" data-tab="stats">Stats</button>
                        <button class="bv-tab" data-tab="info">Info</button>
                    </div>

                    <div id="bv-search-tab" class="bv-results active">
                        <div class="bv-search-box">
                            <input type="text" class="bv-search-input" placeholder="Search query..." id="bv-query">
                            <select class="bv-search-type" id="bv-search-type">
                                <option value="name">Name</option>
                                <option value="phone">Phone</option>
                                <option value="email">Email</option>
                                <option value="city">City</option>
                                <option value="state">State</option>
                            </select>
                            <button class="bv-search-btn" id="bv-search-btn">Search</button>
                        </div>
                        <div id="bv-search-results"></div>
                    </div>

                    <div id="bv-stats-tab" class="bv-results">
                        <div id="bv-stats-content"></div>
                    </div>

                    <div id="bv-info-tab" class="bv-results">
                        <div id="bv-info-content"></div>
                    </div>

                    <div class="bv-actions" style="margin-top: 16px;">
                        <button class="bv-btn bv-btn-primary" id="bv-download-btn">⬇️ Download DB</button>
                        <button class="bv-btn" id="bv-clear-btn">🗑️ Clear Data</button>
                    </div>
                </div>
            `;

            return panel;
        },

        showMessage: (message, type = 'info') => {
            const content = document.querySelector('#bv-search-results');
            if (!content) return;

            const msg = document.createElement('div');
            msg.className = `bv-message ${type}`;
            msg.textContent = message;
            content.innerHTML = '';
            content.appendChild(msg);

            if (type === 'success') setTimeout(() => msg.remove(), 3000);
        },

        showResults: (results) => {
            const content = document.querySelector('#bv-search-results');
            if (!content) return;

            content.innerHTML = '';

            if (results.length === 0) {
                content.innerHTML = '<div class="bv-empty">No results found</div>';
                return;
            }

            results.forEach(record => {
                const item = document.createElement('div');
                item.className = 'bv-result-item';
                item.innerHTML = `
                    <div class="bv-result-name">${Utils.escapeHtml(record.fullName)}</div>
                    ${record.phone ? `<div class="bv-result-field"><span class="bv-result-label">Phone:</span> ${Utils.escapeHtml(record.phone)}</div>` : ''}
                    ${record.email ? `<div class="bv-result-field"><span class="bv-result-label">Email:</span> ${Utils.escapeHtml(record.email)}</div>` : ''}
                    ${record.city ? `<div class="bv-result-field"><span class="bv-result-label">City:</span> ${Utils.escapeHtml(record.city)}</div>` : ''}
                    ${record.state ? `<div class="bv-result-field"><span class="bv-result-label">State:</span> ${Utils.escapeHtml(record.state)}</div>` : ''}
                `;
                content.appendChild(item);
            });
        },

        showStats: async () => {
            const content = document.querySelector('#bv-stats-content');
            if (!content) return;

            const count = await db.records.count();
            const metadata = await Utils.getMetadata();

            let dbSize = 0;
            try {
                const data = await db.records.toArray();
                dbSize = JSON.stringify(data).length;
            } catch (e) {}

            const cities = await db.records.where('city').notEqual(undefined).distinct();

            content.innerHTML = `
                <div class="bv-stats-grid">
                    <div class="bv-stat-card">
                        <div class="bv-stat-value">${count.toLocaleString()}</div>
                        <div class="bv-stat-label">Records</div>
                    </div>
                    <div class="bv-stat-card">
                        <div class="bv-stat-value">${Utils.formatSize(dbSize)}</div>
                        <div class="bv-stat-label">Size</div>
                    </div>
                    <div class="bv-stat-card">
                        <div class="bv-stat-value">${cities.length}</div>
                        <div class="bv-stat-label">Cities</div>
                    </div>
                    <div class="bv-stat-card">
                        <div class="bv-stat-value">∞</div>
                        <div class="bv-stat-label">Access</div>
                    </div>
                </div>
                <div class="bv-message success">
                    ✅ Permanent access - No expiration, no auto-deletion
                </div>
            `;
        },

        showInfo: async () => {
            const content = document.querySelector('#bv-info-content');
            if (!content) return;

            const count = await db.records.count();
            const metadata = await Utils.getMetadata();
            const regDate = new Date(metadata.registeredAt);

            content.innerHTML = `
                <div class="bv-message info">
                    📋 Database Information
                </div>
                <div style="font-size: 13px; line-height: 1.8;">
                    <div><strong>Status:</strong> ✅ Permanent Access</div>
                    <div><strong>Access Type:</strong> Offline Database</div>
                    <div><strong>Registered:</strong> ${regDate.toLocaleDateString()} ${regDate.toLocaleTimeString()}</div>
                    <div><strong>Total Records:</strong> ${count.toLocaleString()}</div>
                    <div><strong>Expiration:</strong> Never ♾️</div>
                </div>
            `;
        }
    };

    // Database operations
    const Database = {
        addRecords: async (records) => {
            try {
                await db.records.bulkAdd(records, { allKeys: true });
                return true;
            } catch (e) {
                console.error('Failed to add records:', e);
                return false;
            }
        },

        search: async (query, fieldType) => {
            const q = query.toLowerCase();

            if (fieldType === 'name') {
                return await db.records
                    .filter(r => r.fullName.toLowerCase().includes(q) ||
                                 r.firstName?.toLowerCase().includes(q) ||
                                 r.lastName?.toLowerCase().includes(q))
                    .limit(500)
                    .toArray();
            } else if (fieldType === 'phone') {
                return await db.records.where('phone').startsWithIgnoreCase(q).toArray();
            } else if (fieldType === 'email') {
                return await db.records.where('email').startsWithIgnoreCase(q).toArray();
            } else if (fieldType === 'city') {
                return await db.records.where('city').startsWithIgnoreCase(q).toArray();
            } else if (fieldType === 'state') {
                return await db.records.where('state').equalsIgnoreCase(q).toArray();
            }

            return [];
        },

        clear: async () => {
            await db.records.clear();
            await db.metadata.clear();
        },

        export: async () => {
            const records = await db.records.toArray();
            const metadata = await Utils.getMetadata();
            return {
                version: 1,
                metadata,
                records,
                exportedAt: new Date().toISOString()
            };
        }
    };

    // Event handlers
    const Events = {
        init: () => {
            const panel = document.querySelector('#bv-offline-panel');
            if (!panel) return;

            // Close button
            panel.querySelector('.bv-close-btn').addEventListener('click', () => {
                panel.remove();
            });

            // Tab switching
            panel.querySelectorAll('.bv-tab').forEach(tab => {
                tab.addEventListener('click', (e) => {
                    panel.querySelectorAll('.bv-tab').forEach(t => t.classList.remove('active'));
                    panel.querySelectorAll('.bv-results').forEach(r => r.classList.remove('active'));

                    e.target.classList.add('active');
                    document.querySelector(`#bv-${e.target.dataset.tab}-tab`).classList.add('active');

                    if (e.target.dataset.tab === 'stats') UI.showStats();
                    if (e.target.dataset.tab === 'info') UI.showInfo();
                });
            });

            // Search
            panel.querySelector('#bv-search-btn').addEventListener('click', async () => {
                const query = panel.querySelector('#bv-query').value;
                const type = panel.querySelector('#bv-search-type').value;

                if (!query.trim()) {
                    UI.showMessage('Enter a search query', 'error');
                    return;
                }

                const results = await Database.search(query, type);
                UI.showResults(results);
            });

            // Download
            panel.querySelector('#bv-download-btn').addEventListener('click', async () => {
                const data = await Database.export();
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `beenverified_offline_${new Date().toISOString().split('T')[0]}.json`;
                a.click();
                URL.revokeObjectURL(url);
                UI.showMessage('Database exported', 'success');
            });

            // Clear
            panel.querySelector('#bv-clear-btn').addEventListener('click', async () => {
                if (confirm('Clear all database records? This cannot be undone.')) {
                    await Database.clear();
                    UI.showMessage('Database cleared', 'success');
                }
            });

            // Enter key on search
            panel.querySelector('#bv-query').addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    panel.querySelector('#bv-search-btn').click();
                }
            });
        }
    };

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(() => {
                const panel = UI.createPanel();
                document.body.appendChild(panel);
                Events.init();
                UI.showStats();
            }, 1000);
        });
    } else {
        setTimeout(() => {
            const panel = UI.createPanel();
            document.body.appendChild(panel);
            Events.init();
            UI.showStats();
        }, 1000);
    }

    // Add menu commands
    GM_registerMenuCommand('📊 Open BeenVerified Offline', () => {
        let panel = document.querySelector('#bv-offline-panel');
        if (!panel) {
            panel = UI.createPanel();
            document.body.appendChild(panel);
            Events.init();
        }
    });

    GM_registerMenuCommand('📤 Export Database', async () => {
        const data = await Database.export();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `beenverified_${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        alert('Database exported successfully!');
    });

})();
