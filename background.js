// Background service worker for Ultimate Email Scraper Extension
class EmailScraperBackground {
  constructor() {
    this.currentJob = null;
    this.apiBaseUrl = 'https://api.emailscraper.pro';
    this.init();
  }

  init() {
    // Listen for messages from popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });

    // Handle extension install/uninstall
    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstall(details);
    });

    // Handle uninstall URL
    chrome.runtime.setUninstallURL('https://emailscraper.pro/uninstall-survey');

    // Periodic cleanup
    setInterval(() => {
      this.cleanup();
    }, 5 * 60 * 1000); // Every 5 minutes
  }

  async handleMessage(message, sender, sendResponse) {
    try {
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

        default:
          sendResponse({ error: 'Unknown action' });
      }
    } catch (error) {
      console.error('Background message error:', error);
      sendResponse({ error: error.message });
    }
  }

  handleInstall(details) {
    if (details.reason === 'install') {
      // First install - open welcome page
      chrome.tabs.create({
        url: 'https://emailscraper.pro/welcome'
      });
    } else if (details.reason === 'update') {
      // Extension updated
      console.log('Extension updated to version', chrome.runtime.getManifest().version);
    }
  }

  async startScraping(jobData) {
    if (this.currentJob && this.currentJob.status === 'running') {
      throw new Error('Another scraping job is already running');
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
      id: this.generateJobId(),
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

    // Start processing
    this.processUrls();
  }

  async processUrls() {
    if (!this.currentJob) return;

    try {
      // Send job to secure API for processing
      const response = await fetch(`${this.apiBaseUrl}/scrape/start`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.currentJob.userToken}`,
          'X-Extension-Version': chrome.runtime.getManifest().version
        },
        body: JSON.stringify({
          jobId: this.currentJob.id,
          urls: this.currentJob.urls,
          config: this.currentJob.config
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.message || 'Failed to start scraping job');
      }

      const jobInfo = await response.json();
      this.currentJob.remoteJobId = jobInfo.jobId;

      // Start polling for updates
      this.pollJobStatus();

    } catch (error) {
      console.error('Failed to start scraping:', error);
      this.sendMessageToPopup({
        type: 'scrapingError',
        data: { message: error.message }
      });
      this.currentJob = null;
    }
  }

  async pollJobStatus() {
    if (!this.currentJob || this.currentJob.status !== 'running') {
      return;
    }

    try {
      const response = await fetch(`${this.apiBaseUrl}/scrape/status/${this.currentJob.remoteJobId}`, {
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

    // Store results for potential export
    chrome.storage.local.set({
      lastResults: this.currentJob.results,
      lastJobStats: {
        totalEmails: finalStatus.totalEmails,
        uniqueDomains: finalStatus.uniqueDomains,
        successRate: finalStatus.successRate,
        completedAt: new Date().toISOString()
      }
    });

    // Clean up
    setTimeout(() => {
      this.currentJob = null;
    }, 60000); // Keep job data for 1 minute
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
      await fetch(`${this.apiBaseUrl}/scrape/pause/${this.currentJob.remoteJobId}`, {
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
        await fetch(`${this.apiBaseUrl}/scrape/stop/${this.currentJob.remoteJobId}`, {
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
      const response = await fetch(`${this.apiBaseUrl}/auth/validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });

      return response.ok;
    } catch (error) {
      console.error('Token validation error:', error);
      return false;
    }
  }

  sendMessageToPopup(message) {
    // Send message to all extension contexts (popup, options, etc.)
    chrome.runtime.sendMessage(message).catch(() => {
      // Popup might be closed, ignore error
    });
  }

  generateJobId() {
    return 'job_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
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
  }
}

// Initialize background service
new EmailScraperBackground();