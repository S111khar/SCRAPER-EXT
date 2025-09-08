// Ultimate Email Scraper Pro - Secure Background Service Worker
class SecureEmailScraperBackground {
  constructor() {
    this.currentJob = null;
    this.apiBaseUrl = 'https://api.emailscraper.pro';
    this.encryptionKey = null;
    this.tamperDetected = false;
    this.cloudFallbackActive = false;
    
    // Anti-tampering and security
    this.integrityChecks = new Map();
    this.lastHeartbeat = Date.now();
    
    this.init();
  }

  init() {
    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });

    // Handle extension lifecycle
    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstall(details);
    });

    chrome.runtime.onStartup.addListener(() => {
      this.handleStartup();
    });

    // Set uninstall URL with survey
    chrome.runtime.setUninstallURL('https://emailscraper.pro/uninstall-survey');

    // Initialize security measures
    this.initializeSecurity();

    // Periodic maintenance and security checks
    setInterval(() => {
      this.performSecurityChecks();
      this.cleanup();
    }, 30000); // Every 30 seconds

    // Heartbeat for tamper detection
    setInterval(() => {
      this.sendHeartbeat();
    }, 60000); // Every minute
  }

  async initializeSecurity() {
    try {
      // Generate client-specific encryption key
      this.encryptionKey = await this.generateEncryptionKey();
      
      // Initialize integrity checks
      await this.setupIntegrityChecks();
      
      // Check for tampering attempts
      await this.detectTampering();
      
      console.log('Security initialized successfully');
    } catch (error) {
      console.error('Security initialization failed:', error);
      this.activateCloudFallback('Security initialization failed');
    }
  }

  async generateEncryptionKey() {
    const key = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return key;
  }

  async setupIntegrityChecks() {
    // Store checksums of critical extension files
    const manifest = chrome.runtime.getManifest();
    this.integrityChecks.set('manifest', this.hashString(JSON.stringify(manifest)));
    
    // Add more integrity checks as needed
    this.integrityChecks.set('version', manifest.version);
    this.integrityChecks.set('permissions', JSON.stringify(manifest.permissions));
  }

  hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
  }

  async detectTampering() {
    try {
      // Check if extension files have been modified
      const manifest = chrome.runtime.getManifest();
      const currentManifestHash = this.hashString(JSON.stringify(manifest));
      
      if (this.integrityChecks.get('manifest') !== currentManifestHash) {
        this.tamperDetected = true;
        this.activateCloudFallback('Manifest tampering detected');
        return;
      }

      // Check for debugging tools
      if (this.isDebuggingDetected()) {
        this.tamperDetected = true;
        this.activateCloudFallback('Debugging tools detected');
        return;
      }

      // Check for suspicious modifications
      if (await this.checkForSuspiciousActivity()) {
        this.tamperDetected = true;
        this.activateCloudFallback('Suspicious activity detected');
        return;
      }

    } catch (error) {
      console.error('Tamper detection error:', error);
      this.activateCloudFallback('Tamper detection failed');
    }
  }

  isDebuggingDetected() {
    // Simple debugging detection
    const start = performance.now();
    debugger; // This will pause if dev tools are open
    const end = performance.now();
    
    return (end - start) > 100; // If paused for more than 100ms, likely debugging
  }

  async checkForSuspiciousActivity() {
    // Check for unusual storage patterns
    const storage = await chrome.storage.local.get(null);
    const suspiciousKeys = ['injected', 'modified', 'hacked', 'bypass'];
    
    for (const key of Object.keys(storage)) {
      if (suspiciousKeys.some(suspicious => key.toLowerCase().includes(suspicious))) {
        return true;
      }
    }

    return false;
  }

  activateCloudFallback(reason) {
    console.warn('Activating cloud fallback:', reason);
    this.cloudFallbackActive = true;
    
    // Notify popup about cloud fallback
    this.sendMessageToPopup({
      type: 'cloudFallback',
      data: { reason, active: true }
    });

    // Clear any local processing capabilities
    this.currentJob = null;
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      // Verify message integrity
      if (!this.verifyMessageIntegrity(message)) {
        sendResponse({ error: 'Message integrity check failed' });
        return;
      }

      switch (message.action) {
        case 'startScraping':
          await this.startScraping(message.data);
          sendResponse({ success: true });
          break;

        case 'pauseScraping':
          await this.pauseScraping();
          sendResponse({ success: true });
          break;

        case 'stopScraping':
          await this.stopScraping();
          sendResponse({ success: true });
          break;

        case 'getJobStatus':
          sendResponse({ job: this.currentJob });
          break;

        case 'securityCheck':
          const isSecure = await this.performSecurityCheck();
          sendResponse({ secure: isSecure });
          break;

        default:
          sendResponse({ error: 'Unknown action' });
      }
    } catch (error) {
      console.error('Background message error:', error);
      sendResponse({ error: error.message });
    }
  }

  verifyMessageIntegrity(message) {
    // Basic message validation
    if (!message || typeof message !== 'object') {
      return false;
    }

    if (!message.action || typeof message.action !== 'string') {
      return false;
    }

    // Add more sophisticated integrity checks as needed
    return true;
  }

  handleInstall(details) {
    if (details.reason === 'install') {
      // First install - open welcome page
      chrome.tabs.create({
        url: 'https://emailscraper.pro/welcome?source=extension'
      });
      
      // Initialize first-time setup
      this.performFirstTimeSetup();
    } else if (details.reason === 'update') {
      // Extension updated
      console.log('Extension updated to version', chrome.runtime.getManifest().version);
      
      // Re-initialize security after update
      setTimeout(() => {
        this.initializeSecurity();
      }, 1000);
    }
  }

  handleStartup() {
    console.log('Extension started');
    this.initializeSecurity();
  }

  async performFirstTimeSetup() {
    try {
      // Generate unique client ID
      const clientId = this.generateClientId();
      await chrome.storage.local.set({ 
        clientId,
        installDate: Date.now(),
        version: chrome.runtime.getManifest().version
      });

      // Register with server
      await this.registerClient(clientId);
    } catch (error) {
      console.error('First-time setup failed:', error);
    }
  }

  generateClientId() {
    return 'client_' + Date.now() + '_' + Math.random().toString(36).substr(2, 16);
  }

  async registerClient(clientId) {
    try {
      await fetch(`${this.apiBaseUrl}/clients/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Extension-Version': chrome.runtime.getManifest().version
        },
        body: JSON.stringify({
          clientId,
          userAgent: navigator.userAgent,
          installDate: Date.now()
        })
      });
    } catch (error) {
      console.error('Client registration failed:', error);
    }
  }

  async startScraping(jobData) {
    if (this.currentJob && this.currentJob.status === 'running') {
      throw new Error('Another scraping job is already running');
    }

    // Security check before starting
    if (this.tamperDetected || this.cloudFallbackActive) {
      return this.startCloudScraping(jobData);
    }

    // Validate auth token
    const isValidToken = await this.validateToken(jobData.userToken);
    if (!isValidToken) {
      this.sendMessageToPopup({
        type: 'scrapingError',
        data: { message: 'Authentication failed. Please sign in again.' }
      });
      return;
    }

    // Create job
    this.currentJob = {
      id: jobData.jobId,
      status: 'running',
      startTime: Date.now(),
      urls: jobData.urls,
      config: jobData.config,
      userToken: jobData.userToken,
      processedUrls: 0,
      foundEmails: 0,
      results: [],
      errors: []
    };

    // Start processing (always use cloud for security)
    await this.startCloudScraping(jobData);
  }

  async startCloudScraping(jobData) {
    try {
      // Send job to secure cloud API
      const response = await this.secureRequest('/scrape/start', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${jobData.userToken}`,
          'X-Extension-Version': chrome.runtime.getManifest().version,
          'X-Client-ID': await this.getClientId(),
          'X-Integrity-Hash': await this.generateIntegrityHash()
        },
        body: JSON.stringify({
          jobId: jobData.jobId,
          urls: jobData.urls,
          config: jobData.config,
          cloudFallback: this.cloudFallbackActive
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Failed to start scraping job');
      }

      const jobInfo = await response.json();
      
      if (this.currentJob) {
        this.currentJob.remoteJobId = jobInfo.jobId;
        this.currentJob.cloudMode = true;
      }

      // Start polling for updates
      this.pollJobStatus();

    } catch (error) {
      console.error('Failed to start cloud scraping:', error);
      this.sendMessageToPopup({
        type: 'scrapingError',
        data: { message: error.message }
      });
      this.currentJob = null;
    }
  }

  async secureRequest(endpoint, options = {}) {
    const url = `${this.apiBaseUrl}${endpoint}`;
    
    // Add security headers
    const secureHeaders = {
      'X-Timestamp': Date.now().toString(),
      'X-Nonce': this.generateNonce(),
      ...options.headers
    };

    return fetch(url, {
      ...options,
      headers: secureHeaders
    });
  }

  generateNonce() {
    return Math.random().toString(36).substr(2, 16);
  }

  async getClientId() {
    const result = await chrome.storage.local.get(['clientId']);
    return result.clientId || 'unknown';
  }

  async generateIntegrityHash() {
    const data = [
      chrome.runtime.getManifest().version,
      await this.getClientId(),
      Date.now().toString()
    ].join('|');
    
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substr(0, 32);
  }

  async pollJobStatus() {
    if (!this.currentJob || this.currentJob.status !== 'running') {
      return;
    }

    try {
      const response = await this.secureRequest(`/scrape/status/${this.currentJob.remoteJobId}`, {
        headers: {
          'Authorization': `Bearer ${this.currentJob.userToken}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to get job status');
      }

      const status = await response.json();

      // Update local job status
      this.currentJob.processedUrls = status.processedUrls;
      this.currentJob.foundEmails = status.foundEmails;

      // Send progress update to popup
      this.sendMessageToPopup({
        type: 'scrapingProgress',
        data: {
          processed: status.processedUrls,
          total: this.currentJob.urls.length,
          emailsFound: status.foundEmails
        }
      });

      // Send new results
      if (status.newResults && status.newResults.length > 0) {
        status.newResults.forEach(result => {
          this.currentJob.results.push(result);
          this.sendMessageToPopup({
            type: 'scrapingResult',
            data: result
          });
        });
      }

      // Send log entries
      if (status.logEntries && status.logEntries.length > 0) {
        status.logEntries.forEach(entry => {
          this.sendMessageToPopup({
            type: 'scrapingLog',
            data: entry
          });
        });
      }

      // Check if job is complete
      if (status.status === 'completed') {
        this.handleJobComplete(status);
      } else if (status.status === 'failed') {
        this.handleJobError(status.error);
      } else {
        // Continue polling
        setTimeout(() => {
          this.pollJobStatus();
        }, 2000); // Poll every 2 seconds
      }

    } catch (error) {
      console.error('Job status polling error:', error);
      
      // Retry polling with exponential backoff
      const retryDelay = Math.min(30000, 2000 * Math.pow(2, this.currentJob.pollRetries || 0));
      this.currentJob.pollRetries = (this.currentJob.pollRetries || 0) + 1;
      
      if (this.currentJob.pollRetries < 5) {
        setTimeout(() => {
          this.pollJobStatus();
        }, retryDelay);
      } else {
        this.handleJobError('Lost connection to scraping service');
      }
    }
  }

  handleJobComplete(finalStatus) {
    if (!this.currentJob) return;

    this.currentJob.status = 'completed';
    this.currentJob.endTime = Date.now();

    // Send completion message
    this.sendMessageToPopup({
      type: 'scrapingComplete',
      data: {
        totalEmails: finalStatus.totalEmails,
        uniqueDomains: finalStatus.uniqueDomains,
        successRate: finalStatus.successRate,
        duration: this.currentJob.endTime - this.currentJob.startTime
      }
    });

    // Store results securely
    this.storeResults(this.currentJob.results, finalStatus);

    // Clean up
    setTimeout(() => {
      this.currentJob = null;
    }, 60000); // Keep job data for 1 minute
  }

  async storeResults(results, stats) {
    try {
      // Encrypt results before storing
      const encryptedResults = await this.encryptData(JSON.stringify(results));
      
      await chrome.storage.local.set({
        lastResults: encryptedResults,
        lastJobStats: {
          totalEmails: stats.totalEmails,
          uniqueDomains: stats.uniqueDomains,
          successRate: stats.successRate,
          completedAt: new Date().toISOString()
        }
      });
    } catch (error) {
      console.error('Failed to store results:', error);
    }
  }

  async encryptData(data) {
    if (!this.encryptionKey) {
      return data; // Fallback to unencrypted if key not available
    }

    try {
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        this.encryptionKey,
        dataBuffer
      );

      // Combine IV and encrypted data
      const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
      combined.set(iv);
      combined.set(new Uint8Array(encryptedBuffer), iv.length);
      
      return Array.from(combined);
    } catch (error) {
      console.error('Encryption failed:', error);
      return data; // Fallback to unencrypted
    }
  }

  handleJobError(error) {
    if (!this.currentJob) return;

    this.currentJob.status = 'failed';
    this.currentJob.endTime = Date.now();

    this.sendMessageToPopup({
      type: 'scrapingError',
      data: { message: error || 'Scraping job failed' }
    });

    this.currentJob = null;
  }

  async pauseScraping() {
    if (!this.currentJob || this.currentJob.status !== 'running') {
      return;
    }

    try {
      await this.secureRequest(`/scrape/pause/${this.currentJob.remoteJobId}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.currentJob.userToken}`
        }
      });

      this.currentJob.status = 'paused';
    } catch (error) {
      console.error('Failed to pause scraping:', error);
    }
  }

  async stopScraping() {
    if (!this.currentJob) {
      return;
    }

    try {
      if (this.currentJob.remoteJobId) {
        await this.secureRequest(`/scrape/stop/${this.currentJob.remoteJobId}`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.currentJob.userToken}`
          }
        });
      }
    } catch (error) {
      console.error('Failed to stop scraping:', error);
    } finally {
      this.currentJob = null;
    }
  }

  async validateToken(token) {
    try {
      const response = await this.secureRequest('/auth/validate', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      return response.ok;
    } catch (error) {
      console.error('Token validation error:', error);
      return false;
    }
  }

  async performSecurityChecks() {
    try {
      // Check for tampering
      await this.detectTampering();
      
      // Verify extension integrity
      const integrityOk = await this.verifyExtensionIntegrity();
      if (!integrityOk) {
        this.activateCloudFallback('Extension integrity check failed');
      }

      // Update heartbeat
      this.lastHeartbeat = Date.now();
      
    } catch (error) {
      console.error('Security check failed:', error);
      this.activateCloudFallback('Security check failed');
    }
  }

  async verifyExtensionIntegrity() {
    try {
      const manifest = chrome.runtime.getManifest();
      
      // Check if manifest has been modified
      const expectedVersion = '1.0.0'; // This should be dynamically set
      if (manifest.version !== expectedVersion) {
        return false;
      }

      // Check permissions
      const requiredPermissions = ['storage', 'downloads', 'activeTab'];
      for (const permission of requiredPermissions) {
        if (!manifest.permissions.includes(permission)) {
          return false;
        }
      }

      return true;
    } catch (error) {
      console.error('Integrity verification failed:', error);
      return false;
    }
  }

  async sendHeartbeat() {
    try {
      const clientId = await this.getClientId();
      await this.secureRequest('/heartbeat', {
        method: 'POST',
        headers: {
          'X-Client-ID': clientId
        },
        body: JSON.stringify({
          timestamp: Date.now(),
          status: this.currentJob ? 'active' : 'idle',
          tamperDetected: this.tamperDetected,
          cloudFallback: this.cloudFallbackActive
        })
      });
    } catch (error) {
      console.error('Heartbeat failed:', error);
    }
  }

  sendMessageToPopup(message) {
    // Send message to all extension contexts (popup, options, etc.)
    chrome.runtime.sendMessage(message).catch(() => {
      // Popup might be closed, ignore error
    });
  }

  cleanup() {
    // Clean up old stored data
    chrome.storage.local.get(['lastResults', 'lastJobStats'], (result) => {
      if (result.lastJobStats && result.lastJobStats.completedAt) {
        const completedAt = new Date(result.lastJobStats.completedAt);
        const now = new Date();
        const daysDiff = (now - completedAt) / (1000 * 60 * 60 * 24);

        // Remove results older than 7 days
        if (daysDiff > 7) {
          chrome.storage.local.remove(['lastResults', 'lastJobStats']);
        }
      }
    });

    // Clean up failed jobs
    if (this.currentJob && this.currentJob.status === 'failed') {
      const timeSinceFailure = Date.now() - (this.currentJob.endTime || 0);
      if (timeSinceFailure > 300000) { // 5 minutes
        this.currentJob = null;
      }
    }

    // Clean up old logs and temporary data
    this.cleanupTemporaryData();
  }

  async cleanupTemporaryData() {
    try {
      const storage = await chrome.storage.local.get(null);
      const keysToRemove = [];
      
      for (const [key, value] of Object.entries(storage)) {
        // Remove temporary keys older than 24 hours
        if (key.startsWith('temp_') && value.timestamp) {
          const age = Date.now() - value.timestamp;
          if (age > 24 * 60 * 60 * 1000) {
            keysToRemove.push(key);
          }
        }
      }
      
      if (keysToRemove.length > 0) {
        await chrome.storage.local.remove(keysToRemove);
      }
    } catch (error) {
      console.error('Cleanup failed:', error);
    }
  }

  async performSecurityCheck() {
    return !this.tamperDetected && this.lastHeartbeat > (Date.now() - 120000); // 2 minutes
  }
}

// Initialize background service
new SecureEmailScraperBackground();