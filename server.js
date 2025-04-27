import express from 'express';
import axios from 'axios';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import compression from 'compression';
import helmet from 'helmet';
import { Agent } from 'https';
import rateLimit from 'express-rate-limit';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 5000;

const API_BASE_PATH = process.env.API_BASE_PATH || '/api';

// Axios with connection pooling
const api = axios.create({
  timeout: 10000,
  headers: {
    'Accept': 'application/json'
  },
  maxContentLength: 50 * 1000 * 1000, // 50 MB
  maxBodyLength: 50 * 1000 * 1000, // 50 MB
  httpsAgent: new Agent({ keepAlive: true })
});

// Cache storage
const cache = {
  geocoding: new Map(),
  places: new Map(),
  details: new Map()
};

// Cache configuration
const CACHE_CONFIG = {
  geocoding: {
    expiry: 30 * 60 * 1000,  // 30 minutes
    limit: 1000
  },
  places: {
    expiry: 15 * 60 * 1000,  // 15 minutes
    limit: 500
  },
  details: {
    expiry: 60 * 60 * 1000,  // 60 minutes
    limit: 500
  }
};

// Enhanced request tracking with more flexible limits
const requestStats = {
  total: 0,
  geocoding: 0,
  places: 0,
  details: 0,
  limit: 100, // Increased from 50 to 100
  softLimit: 20, // New soft limit for friendlier user experience
  lastReset: Date.now()
};

// Improved rate limiting mechanism
const rateLimiter = {
  requestLog: [],
  maxRequestsPerMinute: 10,
  minIntervalMs: 200,
  
  canMakeRequest() {
    const now = Date.now();
    
    // Remove old requests (older than 1 minute)
    this.requestLog = this.requestLog.filter(time => now - time < 60000);
    
    // Check number of recent requests
    if (this.requestLog.length >= this.maxRequestsPerMinute) {
      console.log(`Rate limit exceeded: ${this.requestLog.length} requests in the last minute`);
      return false;
    }
    
    // Check minimum interval between requests
    if (this.requestLog.length > 0) {
      const lastRequestTime = this.requestLog[this.requestLog.length - 1];
      if (now - lastRequestTime < this.minIntervalMs) {
        console.log(`Minimum interval not met: ${now - lastRequestTime}ms since last request`);
        return false;
      }
    }
    
    // Log this request
    this.requestLog.push(now);
    return true;
  },
  
  resetRequestLog() {
    this.requestLog = [];
  }
};

// Session reset after 24 hours
function checkSessionReset() {
  if (Date.now() - requestStats.lastReset > 24 * 60 * 60 * 1000) {
    console.log('Resetting session stats (24-hour period elapsed)');
    Object.keys(requestStats).forEach(key => {
      if (typeof requestStats[key] === 'number' && key !== 'limit' && key !== 'softLimit') {
        requestStats[key] = 0;
      }
    });
    
    cache.geocoding.clear();
    cache.places.clear();
    cache.details.clear();
    
    rateLimiter.resetRequestLog();
    
    requestStats.lastReset = Date.now();
  }
}

// Cache size management
function manageCacheSize(type) {
  const cacheMap = cache[type];
  const limit = CACHE_CONFIG[type].limit;
  
  if (cacheMap.size > limit) {
    console.log(`Cache ${type} exceeded limit (${cacheMap.size}/${limit}), purging oldest items`);
    
    const entries = Array.from(cacheMap.entries())
      .sort((a, b) => a[1].timestamp - b[1].timestamp);
    
    const removeCount = Math.floor(entries.length * 0.2);
    for (let i = 0; i < removeCount; i++) {
      cacheMap.delete(entries[i][0]);
    }
    
    console.log(`Removed ${removeCount} items from ${type} cache`);
  }
}

const cspConfig = {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'", "https://maps.googleapis.com", "https://cdnjs.cloudflare.com"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    imgSrc: ["'self'", "data:", "https://maps.googleapis.com", "https://maps.gstatic.com"],
    connectSrc: ["'self'", "https://maps.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    objectSrc: ["'none'"]
  }
};

// Global rate limiter with more generous settings
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Allow 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests from this IP, please try again later.'
});

// Different security settings based on environment
if (process.env.NODE_ENV === 'production') {
  // Full security in production
  app.use(helmet({
    contentSecurityPolicy: cspConfig
  }));
} else {
  // Reduced security headers for development
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginEmbedderPolicy: false,
    originAgentCluster: false
  }));
}

app.use(compression());

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? [process.env.FRONTEND_URL || 'https://yourdomain.com']
    : '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json({ limit: '1mb' }));

app.use(API_BASE_PATH, apiLimiter);

if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
  });
}

if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'dist')));
}

app.use((req, res, next) => {
  checkSessionReset();
  next();
});

async function handleCachedRequest(type, cacheKey, apiUrl) {
  const cachedItem = cache[type].get(cacheKey);
  if (cachedItem && (Date.now() - cachedItem.timestamp < CACHE_CONFIG[type].expiry)) {
    cachedItem.lastAccessed = Date.now();
    console.log(`Using cached ${type} data for ${cacheKey}`);
    return cachedItem.data;
  }
  
  // More flexible request limiting
  if (requestStats.total >= requestStats.limit) {
    throw new Error('Request limit reached');
  }
  
  // Implement the new rate limiter
  if (!rateLimiter.canMakeRequest()) {
    // Distinguish between soft and hard limits
    if (requestStats.total >= requestStats.softLimit) {
      throw new Error('Too many requests. Please wait a moment and try again.');
    }
    // If below soft limit, allow the request but with a slight delay
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  
  try {
    console.log(`Making ${type} API request to Google Maps: ${apiUrl.replace(/key=[^&]+/, 'key=REDACTED')}`);
    
    const response = await api.get(apiUrl);
    
    console.log(`Google API response status: ${response.data.status}`);
    
    requestStats.total++;
    requestStats[type]++;
    
    if (response.data.status !== 'OK' && response.data.status !== 'ZERO_RESULTS') {
      console.error(`Google Maps API error: ${response.data.status}`);
      if (response.data.error_message) {
        console.error(`Error message: ${response.data.error_message}`);
      }
      throw new Error(`Google Maps API error: ${response.data.status}`);
    }
    
    if (response.data.status === 'OK' || response.data.status === 'ZERO_RESULTS') {
      cache[type].set(cacheKey, {
        data: response.data,
        timestamp: Date.now(),
        lastAccessed: Date.now()
      });
      
      manageCacheSize(type);
    }
    
    return response.data;
  } catch (error) {
    console.error(`Error in ${type} request:`, error.message);
    
    if (error.response) {
      console.error('Response data:', error.response.data);
      console.error('Response status:', error.response.status);
    } else if (error.request) {
      console.error('No response received');
    }
    
    throw error;
  }
}

// Validation helpers
function validateCoordinates(lat, lng) {
  const latNum = parseFloat(lat);
  const lngNum = parseFloat(lng);
  
  if (isNaN(latNum) || isNaN(lngNum)) {
    return false;
  }
  
  if (latNum < -90 || latNum > 90 || lngNum < -180 || lngNum > 180) {
    return false;
  }
  
  return true;
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[<>]/g, '');
}

// Batch geocoding helper
async function batchGeocode(addresses) {
  const results = [];
  const errors = [];
  
  const validatedAddresses = addresses.filter(addr => {
    if (typeof addr !== 'string' || addr.trim().length === 0) {
      errors.push({ address: addr, error: 'Invalid address format' });
      return false;
    }
    return true;
  }).map(addr => sanitizeInput(addr));
  
  const batchSize = 5;
  
  for (let i = 0; i < validatedAddresses.length; i += batchSize) {
    const batch = validatedAddresses.slice(i, i + batchSize);
    const promises = batch.map(async (address) => {
      try {
        const normalizedAddress = address.toLowerCase().trim();
        const cacheKey = normalizedAddress;
        const apiUrl = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(address)}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
        
        const data = await handleCachedRequest('geocoding', cacheKey, apiUrl);
        return { address, data };
      } catch (error) {
        return { address, error: error.message };
      }
    });
    
    const batchResults = await Promise.all(promises);
    
    for (const result of batchResults) {
      if (result.error) {
        errors.push({ address: result.address, error: result.error });
      } else {
        results.push({ address: result.address, data: result.data });
      }
    }
    
    if (i + batchSize < validatedAddresses.length) {
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }
  
  return { results, errors };
}

const apiRoutes = express.Router();

// Root route handler
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Rendezvous Server</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
          }
          h1 {
            color: #333;
          }
          .api-info {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
          }
        </style>
      </head>
      <body>
        <h1>Rendezvous Server</h1>
        <p>Welcome to the Rendezvous Server! This service provides geocoding and places API functionality.</p>
        
        <div class="api-info">
          <p>Server Status: <strong>Online</strong></p>
          <p>API Endpoints available at: <code>${API_BASE_PATH}</code></p>
        </div>
      </body>
    </html>
  `);
});

// Health check endpoint
apiRoutes.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'Server is running',
    requestStats: {
      total: requestStats.total,
      limit: requestStats.limit,
      softLimit: requestStats.softLimit
    }
  });
});

// API Key verification endpoint
if (process.env.NODE_ENV !== 'production') {
  apiRoutes.get('/verify-key', (req, res) => {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    
    if (!apiKey) {
      return res.status(500).json({ 
        status: 'ERROR', 
        message: 'API key not found in environment variables' 
      });
    }
    
    res.json({ 
      status: 'OK', 
      message: 'API key found', 
      keyPreview: `${apiKey.substring(0, 4)}...${apiKey.substring(apiKey.length - 4)}` 
    });
  });
}

// Stats endpoint
apiRoutes.get('/stats', (req, res) => {
  checkSessionReset();
  res.json({
    requestStats,
    cacheStats: {
      geocoding: cache.geocoding.size,
      places: cache.places.size,
      details: cache.details.size
    }
  });
});

// Reset stats endpoint
apiRoutes.post('/stats/reset', (req, res) => {
  if (process.env.NODE_ENV === 'production' && (!req.headers.authorization || req.headers.authorization !== `Bearer ${process.env.ADMIN_API_KEY}`)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  console.log('Manually resetting API stats');
  Object.keys(requestStats).forEach(key => {
    if (typeof requestStats[key] === 'number' && key !== 'limit' && key !== 'softLimit') {
      requestStats[key] = 0;
    }
  });
  requestStats.lastReset = Date.now();
  
  rateLimiter.resetRequestLog();
  
  cache.geocoding.clear();
  cache.places.clear();
  cache.details.clear();
  
  res.json({ message: 'Stats reset successfully', requestStats });
});

// Geocoding endpoint
apiRoutes.get('/geocode', async (req, res) => {
  const address = req.query.address;
  
  if (!address) {
    return res.status(400).json({ error: 'Address is required' });
  }
  
  try {
    const sanitizedAddress = sanitizeInput(address);
    const normalizedAddress = sanitizedAddress.toLowerCase().trim();
    const cacheKey = normalizedAddress;
    const apiUrl = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(sanitizedAddress)}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    
    const data = await handleCachedRequest('geocoding', cacheKey, apiUrl);
    
    // Add some extra helpful information to the response
    const responseData = {
      ...data,
      requestStats: {
        total: requestStats.total,
        limit: requestStats.limit,
        softLimit: requestStats.softLimit
      }
    };
    
    res.json(responseData);
  } catch (error) {
    // Provide more informative error response
    res.status(500).json({ 
      error: error.message,
      requestStats: {
        total: requestStats.total,
        limit: requestStats.limit,
        softLimit: requestStats.softLimit
      }
    });
  }
});

// Batch geocoding endpoint
apiRoutes.post('/geocode/batch', async (req, res) => {
  const { addresses } = req.body;
  
  if (!addresses || !Array.isArray(addresses) || addresses.length === 0) {
    return res.status(400).json({ error: 'Array of addresses is required' });
  }
  
  // Limit batch size to prevent abuse
  if (addresses.length > 10) {
    return res.status(400).json({ 
      error: 'Too many addresses. Maximum 10 addresses allowed per batch request.',
      maxAddressesAllowed: 10
    });
  }
  
  try {
    const results = await batchGeocode(addresses);
    
    // Add request stats to the response
    const responseData = {
      ...results,
      requestStats: {
        total: requestStats.total,
        limit: requestStats.limit,
        softLimit: requestStats.softLimit
      }
    };
    
    res.json(responseData);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      requestStats: {
        total: requestStats.total,
        limit: requestStats.limit,
        softLimit: requestStats.softLimit
      }
    });
  }
});

// Nearby places endpoint
apiRoutes.get('/places/nearby', async (req, res) => {
  const { lat, lng, radius, type, pagetoken } = req.query;
  
  if ((!lat || !lng) && !pagetoken) {
    return res.status(400).json({ error: 'Location coordinates required unless using pagetoken' });
  }
  
  try {
    if (pagetoken) {
      if (typeof pagetoken !== 'string' || pagetoken.length > 300) {
        return res.status(400).json({ error: 'Invalid pagetoken format' });
      }
      
      const cacheKey = `pagetoken:${pagetoken}`;
      const apiUrl = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?pagetoken=${encodeURIComponent(pagetoken)}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
      
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      const data = await handleCachedRequest('places', cacheKey, apiUrl);
      res.json(data);
      return;
    }
    
    if (!validateCoordinates(lat, lng)) {
      return res.status(400).json({ error: 'Invalid coordinates format' });
    }
    
    const safeRadius = Math.min(Math.max(parseInt(radius) || 1609.34, 100), 50000);
    const safeType = /^[a-zA-Z_]+$/.test(type) ? type : 'restaurant';
    
    const cacheKey = `${lat},${lng},${safeRadius},${safeType}`;
    const apiUrl = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=${lat},${lng}&radius=${safeRadius}&type=${safeType}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    
    const data = await handleCachedRequest('places', cacheKey, apiUrl);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Place details endpoint
apiRoutes.get('/places/details', async (req, res) => {
  const { placeid, fields } = req.query;
  
  if (!placeid) {
    return res.status(400).json({ error: 'Place ID is required' });
  }
  
  try {
    if (typeof placeid !== 'string' || placeid.length > 300 || !/^[a-zA-Z0-9_\-]+$/.test(placeid)) {
      return res.status(400).json({ error: 'Invalid place ID format' });
    }
    
    let fieldsParam = '';
    if (fields) {
      const allowedFields = ['name', 'rating', 'formatted_address', 'geometry', 'photos', 'price_level', 'opening_hours', 'website'];
      const fieldList = fields.split(',').filter(field => allowedFields.includes(field.trim()));
      if (fieldList.length > 0) {
        fieldsParam = `&fields=${fieldList.join(',')}`;
      }
    }
    
    const cacheKey = `${placeid},${fieldsParam}`;
    const apiUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeid}${fieldsParam}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    
    const data = await handleCachedRequest('details', cacheKey, apiUrl);
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Photo proxy endpoint
apiRoutes.get('/places/photo', async (req, res) => {
  const { photoreference, maxwidth = 400 } = req.query;
  
  if (!photoreference) {
    return res.status(400).json({ error: 'Photo reference is required' });
  }
  
  try {
    if (typeof photoreference !== 'string' || photoreference.length > 500) {
      return res.status(400).json({ error: 'Invalid photo reference' });
    }
    
    const safeMaxWidth = Math.min(Math.max(parseInt(maxwidth) || 400, 100), 1600);
    
    const photoUrl = `https://maps.googleapis.com/maps/api/place/photo?maxwidth=${safeMaxWidth}&photoreference=${encodeURIComponent(photoreference)}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
    
    const photoResponse = await api.get(photoUrl, {
      responseType: 'stream'
    });
    
    res.set('Content-Type', photoResponse.headers['content-type']);
    
    photoResponse.data.pipe(res);
  } catch (error) {
    console.error('Error fetching photo:', error.message);
    res.status(500).json({ error: 'Error fetching photo' });
  }
});

// Batch place details endpoint
apiRoutes.post('/places/details/batch', async (req, res) => {
  const { placeIds, fields } = req.body;
  
  if (!placeIds || !Array.isArray(placeIds) || placeIds.length === 0) {
    return res.status(400).json({ error: 'Array of place IDs is required' });
  }
  
  // Limit batch size to prevent abuse
  if (placeIds.length > 10) {
    return res.status(400).json({ 
      error: 'Too many place IDs. Maximum 10 place IDs allowed per batch request.',
      maxPlaceIdsAllowed: 10
    });
  }
  
  try {
    const results = [];
    const errors = [];
    
    const batchSize = 5;
    
    let fieldsParam = '';
    if (fields && Array.isArray(fields)) {
      const allowedFields = ['name', 'rating', 'formatted_address', 'geometry', 'photos', 'price_level', 'opening_hours', 'website'];
      const fieldList = fields.filter(field => 
        typeof field === 'string' && allowedFields.includes(field.trim())
      );
      if (fieldList.length > 0) {
        fieldsParam = fieldList.join(',');
      }
    }
    
    const validPlaceIds = placeIds.filter(id => 
      typeof id === 'string' && id.length <= 300 && /^[a-zA-Z0-9_\-]+$/.test(id)
    );
    
    if (validPlaceIds.length === 0) {
      return res.status(400).json({ error: 'No valid place IDs provided' });
    }
    
    for (let i = 0; i < validPlaceIds.length; i += batchSize) {
      const batch = validPlaceIds.slice(i, i + batchSize);
      const promises = batch.map(async (placeId) => {
        try {
          const cacheKey = `${placeId},${fieldsParam}`;
          const apiUrl = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${placeId}${fieldsParam ? `&fields=${fieldsParam}` : ''}&key=${process.env.GOOGLE_MAPS_API_KEY}`;
          
          const data = await handleCachedRequest('details', cacheKey, apiUrl);
          return { placeId, data };
        } catch (error) {
          return { placeId, error: error.message };
        }
      });
      
      const batchResults = await Promise.all(promises);
      
      for (const result of batchResults) {
        if (result.error) {
          errors.push({ placeId: result.placeId, error: result.error });
        } else {
          results.push({ placeId: result.placeId, data: result.data });
        }
      }
      
      if (i + batchSize < validPlaceIds.length) {
        await new Promise(resolve => setTimeout(resolve, 200));
      }
    }
    
    // Wrap response with request stats
    const responseData = {
      results, 
      errors,
      requestStats: {
        total: requestStats.total,
        limit: requestStats.limit,
        softLimit: requestStats.softLimit
      }
    };
    
    res.json(responseData);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      requestStats: {
        total: requestStats.total,
        limit: requestStats.limit,
        softLimit: requestStats.softLimit
      }
    });
  }
});

// Mount API routes
app.use(API_BASE_PATH, apiRoutes);

// Catch-all route for SPA in production
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'dist', 'index.html'));
  });
}

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ 
    error: process.env.NODE_ENV === 'production' 
      ? 'Internal server error' 
      : err.message || 'Internal server error', 
    status: 'ERROR',
    requestStats: {
      total: requestStats.total,
      limit: requestStats.limit,
      softLimit: requestStats.softLimit
    }
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API Key exists: ${!!process.env.GOOGLE_MAPS_API_KEY}`);
  
  if (process.env.GOOGLE_MAPS_API_KEY && process.env.NODE_ENV !== 'production') {
    const key = process.env.GOOGLE_MAPS_API_KEY;
    console.log(`API Key preview: ${key.substring(0, 4)}...${key.substring(key.length - 4)}`);
  }
  
  const memoryUsage = process.memoryUsage();
  console.log('Memory usage:', {
    rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
    heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
    heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`
  });
});