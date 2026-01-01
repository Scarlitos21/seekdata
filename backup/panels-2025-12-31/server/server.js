/**
 * SeekData Backend API Server (backup copy)
 * Full snapshot backup: server.js
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const cors = require('cors');
const crypto = require('crypto');

// Import services
const db = require('../server/db-schema');
const authService = require('../server/auth-service');
const searchService = require('../server/search-service');
const sourcesService = require('../server/sources-service');
const adminRoutes = require('../server/admin-routes');

// NOTE: This is a static backup copy for archival purposes.
// It should not be executed from the backup folder.

module.exports = `BACKUP of original server.js taken on 2025-12-31. See original in workspace path: osint-original/server/server.js`;
