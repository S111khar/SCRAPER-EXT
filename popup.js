// Popup script for Ultimate Email Scraper Extension
class EmailScraperUI {
  constructor() {
    this.isAuthenticated = false;
    this.currentUser = null;
    this.scrapingJob = null;
    this.results = [];
    this.isDarkTheme = false;
    
    this.init();
  }

  async init() {
    await this.loadSettings();
    this.setupEventListeners();
    this.setupTheme();
    await this.checkAuthStatus();
    this.updateUI();
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['theme', 'config']);
      this.isDarkTheme = result.theme === 'dark';
      this.config = result.config || this.getDefaultConfig();
    } catch (error) {
      console.error('Failed to load settings:', error);
      this.config = this.getDefaultConfig();
    }
  }

  getDefaultConfig() {
    return {
      concurrent: 8,
      perDomain: 3,
      delayMin: 1.5,
      delayMax: 3.0,
      timeout: 25,
      retries: 2,
      respectRobots: true
    };
  }

  setupEventListeners() {
    // Theme toggle
    document.getElementById('themeToggle').addEventListener('click', () => {
      this.toggleTheme();
    });

    // Auth events
    document.getElementById('loginBtn').addEventListener('click', () => {
      this.handleLogin();
    });

    document.getElementById('logoutBtn').addEventListener('click', () => {
      this.handleLogout();
    });

    document.getElementById('manageSubBtn').addEventListener('click', () => {
      this.openSubscriptionManager();
    });

    document.getElementById('signupLink').addEventListener('click', (e) => {
      e.preventDefault();
      this.openSignup();
    });

    document.getElementById('forgotLink').addEventListener('click', (e) => {
      e.preventDefault();
      this.openPasswordReset();
    });

    // File upload events
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');

    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('dragover', this.handleDragOver.bind(this));
    uploadArea.addEventListener('dragleave', this.handleDragLeave.bind(this));
    uploadArea.addEventListener('drop', this.handleDrop.bind(this));
    fileInput.addEventListener('change', this.handleFileSelect.bind(this));

    document.getElementById('removeFile').addEventListener('click', () => {
      this.removeFile();
    });

    // Config events
    this.setupConfigListeners();

    // Control events
    document.getElementById('startBtn').addEventListener('click', () => {
      this.startScraping();
    });

    document.getElementById('pauseBtn').addEventListener('click', () => {
      this.pauseScraping();
    });

    document.getElementById('stopBtn').addEventListener('click', () => {
      this.stopScraping();
    });

    // Log events
    document.getElementById('clearLogBtn').addEventListener('click', () => {
      this.clearLog();
    });

    // Results events
    document.getElementById('exportCsvBtn').addEventListener('click', () => {
      this.exportResults('csv');
    });

    document.getElementById('exportJsonBtn').addEventListener('click', () => {
      this.exportResults('json');
    });

    document.getElementById('copyResultsBtn').addEventListener('click', () => {
      this.copyResults();
    });

    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleBackgroundMessage(message);
    });
  }

  setupConfigListeners() {
    const configInputs = [
      'concurrentInput', 'perDomainInput', 'delayMinInput', 
      'delayMaxInput', 'timeoutInput', 'retriesInput'
    ];

    configInputs.forEach(id => {
      const input = document.getElementById(id);
      input.addEventListener('change', () => {
        this.updateConfig();
      });
    });

    document.getElementById('respectRobots').addEventListener('change', () => {
      this.updateConfig();
    });
  }

  setupTheme() {
    document.documentElement.setAttribute('data-theme', this.isDarkTheme ? 'dark' : 'light');
  }

  toggleTheme() {
    this.isDarkTheme = !this.isDarkTheme;
    this.setupTheme();
    chrome.storage.local.set({ theme: this.isDarkTheme ? 'dark' : 'light' });
  }

  async checkAuthStatus() {
    try {
      const result = await chrome.storage.local.get(['authToken', 'userInfo']);
      if (result.authToken && result.userInfo) {
        // Verify token with server
        const isValid = await this.verifyToken(result.authToken);
        if (isValid) {
          this.isAuthenticated = true;
          this.currentUser = result.userInfo;
        } else {
          // Token expired, clear storage
          await chrome.storage.local.remove(['authToken', 'userInfo']);
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
    }
  }

  async verifyToken(token) {
    try {
      const response = await fetch('https://api.emailscraper.pro/auth/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      });
      return response.ok;
    } catch (error) {
      console.error('Token verification failed:', error);
      return false;
    }
  }

  async handleLogin() {
    const email = document.getElementById('emailInput').value.trim();
    const password = document.getElementById('passwordInput').value;

    if (!email || !password) {
      this.showError('Please enter both email and password');
      return;
    }

    const loginBtn = document.getElementById('loginBtn');
    const btnText = loginBtn.querySelector('.btn-text');
    const btnSpinner = loginBtn.querySelector('.btn-spinner');

    // Show loading state
    btnText.textContent = 'Signing in...';
    btnSpinner.classList.remove('hidden');
    loginBtn.disabled = true;

    try {
      const response = await fetch('https://api.emailscraper.pro/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        // Store auth data
        await chrome.storage.local.set({
          authToken: data.token,
          userInfo: data.user
        });

        this.isAuthenticated = true;
        this.currentUser = data.user;
        this.updateUI();
        this.addLogEntry('success', 'Successfully signed in');
      } else {
        this.showError(data.message || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      this.showError('Network error. Please try again.');
    } finally {
      // Reset button state
      btnText.textContent = 'Sign In';
      btnSpinner.classList.add('hidden');
      loginBtn.disabled = false;
    }
  }

  async handleLogout() {
    try {
      await chrome.storage.local.remove(['authToken', 'userInfo']);
      this.isAuthenticated = false;
      this.currentUser = null;
      this.updateUI();
      this.addLogEntry('info', 'Signed out successfully');
    } catch (error) {
      console.error('Logout error:', error);
    }
  }

  openSubscriptionManager() {
    chrome.tabs.create({
      url: 'https://billing.emailscraper.pro/manage'
    });
  }

  openSignup() {
    chrome.tabs.create({
      url: 'https://emailscraper.pro/signup'
    });
  }

  openPasswordReset() {
    chrome.tabs.create({
      url: 'https://emailscraper.pro/reset-password'
    });
  }

  handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('uploadArea').classList.add('dragover');
  }

  handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('uploadArea').classList.remove('dragover');
  }

  handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('uploadArea').classList.remove('dragover');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      this.processFile(files[0]);
    }
  }

  handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
      this.processFile(files[0]);
    }
  }

  async processFile(file) {
    // Validate file type
    const validTypes = ['text/csv', 'text/plain', '.csv', '.txt'];
    const isValid = validTypes.some(type => 
      file.type === type || file.name.toLowerCase().endsWith(type)
    );

    if (!isValid) {
      this.showError('Please select a CSV or TXT file');
      return;
    }

    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      this.showError('File size must be less than 10MB');
      return;
    }

    try {
      const content = await this.readFile(file);
      const urls = this.parseUrls(content);

      if (urls.length === 0) {
        this.showError('No valid URLs found in file');
        return;
      }

      // Store file data
      this.fileData = {
        name: file.name,
        size: this.formatFileSize(file.size),
        urls: urls
      };

      this.showFileInfo();
      this.addLogEntry('success', `Loaded ${urls.length} URLs from ${file.name}`);
    } catch (error) {
      console.error('File processing error:', error);
      this.showError('Failed to process file');
    }
  }

  readFile(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = e => resolve(e.target.result);
      reader.onerror = reject;
      reader.readAsText(file);
    });
  }

  parseUrls(content) {
    const lines = content.split('\n');
    const urls = [];
    const urlRegex = /^https?:\/\/[^\s]+$/i;

    for (let line of lines) {
      line = line.trim();
      if (line && !line.startsWith('#')) {
        // Handle CSV format
        if (line.includes(',')) {
          const parts = line.split(',');
          line = parts[0].trim().replace(/['"]/g, '');
        }

        // Add protocol if missing
        if (line && !line.startsWith('http')) {
          line = 'https://' + line;
        }

        // Validate URL format
        if (urlRegex.test(line)) {
          urls.push(line);
        }
      }
    }

    return [...new Set(urls)]; // Remove duplicates
  }

  formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  showFileInfo() {
    document.getElementById('fileName').textContent = this.fileData.name;
    document.getElementById('fileSize').textContent = this.fileData.size;
    document.getElementById('fileInfo').classList.remove('hidden');
  }

  removeFile() {
    this.fileData = null;
    document.getElementById('fileInfo').classList.add('hidden');
    document.getElementById('fileInput').value = '';
    this.addLogEntry('info', 'File removed');
  }

  updateConfig() {
    this.config = {
      concurrent: parseInt(document.getElementById('concurrentInput').value),
      perDomain: parseInt(document.getElementById('perDomainInput').value),
      delayMin: parseFloat(document.getElementById('delayMinInput').value),
      delayMax: parseFloat(document.getElementById('delayMaxInput').value),
      timeout: parseInt(document.getElementById('timeoutInput').value),
      retries: parseInt(document.getElementById('retriesInput').value),
      respectRobots: document.getElementById('respectRobots').checked
    };

    chrome.storage.local.set({ config: this.config });
  }

  async startScraping() {
    if (!this.isAuthenticated) {
      this.showError('Please sign in to start scraping');
      return;
    }

    if (!this.fileData || !this.fileData.urls.length) {
      this.showError('Please upload a file with URLs first');
      return;
    }

    // Check subscription limits
    const canStart = await this.checkLimits();
    if (!canStart) {
      return;
    }

    try {
      // Send scraping job to background script
      const jobData = {
        urls: this.fileData.urls,
        config: this.config,
        userToken: await this.getAuthToken()
      };

      chrome.runtime.sendMessage({
        action: 'startScraping',
        data: jobData
      });

      this.scrapingJob = {
        status: 'running',
        startTime: Date.now(),
        totalUrls: this.fileData.urls.length,
        processedUrls: 0,
        foundEmails: 0
      };

      this.updateControlButtons();
      this.addLogEntry('info', `Started scraping ${this.fileData.urls.length} URLs`);
      
    } catch (error) {
      console.error('Failed to start scraping:', error);
      this.showError('Failed to start scraping');
    }
  }

  async checkLimits() {
    try {
      const token = await this.getAuthToken();
      const response = await fetch('https://api.emailscraper.pro/limits/check', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          urlCount: this.fileData.urls.length
        })
      });

      const data = await response.json();

      if (!response.ok) {
        if (response.status === 402) {
          this.showUpgradeDialog(data.message);
          return false;
        }
        this.showError(data.message || 'Limit check failed');
        return false;
      }

      return true;
    } catch (error) {
      console.error('Limit check error:', error);
      this.showError('Failed to check limits');
      return false;
    }
  }

  showUpgradeDialog(message) {
    if (confirm(`${message}\n\nWould you like to upgrade your subscription?`)) {
      this.openSubscriptionManager();
    }
  }

  async getAuthToken() {
    const result = await chrome.storage.local.get(['authToken']);
    return result.authToken;
  }

  pauseScraping() {
    chrome.runtime.sendMessage({ action: 'pauseScraping' });
    this.scrapingJob.status = 'paused';
    this.updateControlButtons();
    this.addLogEntry('warning', 'Scraping paused');
  }

  stopScraping() {
    chrome.runtime.sendMessage({ action: 'stopScraping' });
    this.scrapingJob = null;
    this.updateControlButtons();
    this.addLogEntry('info', 'Scraping stopped');
  }

  handleBackgroundMessage(message) {
    switch (message.type) {
      case 'scrapingProgress':
        this.updateProgress(message.data);
        break;
      case 'scrapingLog':
        this.addLogEntry(message.data.level, message.data.message);
        break;
      case 'scrapingResult':
        this.addResult(message.data);
        break;
      case 'scrapingComplete':
        this.handleScrapingComplete(message.data);
        break;
      case 'scrapingError':
        this.handleScrapingError(message.data);
        break;
    }
  }

  updateProgress(data) {
    if (this.scrapingJob) {
      this.scrapingJob.processedUrls = data.processed;
      this.scrapingJob.foundEmails = data.emailsFound;
      
      const progress = (data.processed / this.scrapingJob.totalUrls) * 100;
      
      // Update progress bar
      const progressFill = document.querySelector('.progress-fill');
      const progressText = document.querySelector('.progress-text');
      
      progressFill.style.width = `${progress}%`;
      progressText.textContent = `${data.processed}/${this.scrapingJob.totalUrls} processed`;
      
      // Update status info
      document.getElementById('progressText').textContent = `${data.processed}/${this.scrapingJob.totalUrls}`;
      document.getElementById('emailsFoundText').textContent = data.emailsFound;
    }
  }

  addResult(result) {
    this.results.push(result);
    this.updateResultsDisplay();
  }

  handleScrapingComplete(data) {
    this.scrapingJob = null;
    this.updateControlButtons();
    this.addLogEntry('success', `Scraping completed! Found ${data.totalEmails} emails`);
    
    // Hide progress bar
    document.getElementById('progressBar').classList.add('hidden');
    
    // Update final stats
    this.updateResultsStats(data);
  }

  handleScrapingError(error) {
    this.scrapingJob = null;
    this.updateControlButtons();
    this.addLogEntry('error', `Scraping failed: ${error.message}`);
    document.getElementById('progressBar').classList.add('hidden');
  }

  updateControlButtons() {
    const startBtn = document.getElementById('startBtn');
    const pauseBtn = document.getElementById('pauseBtn');
    const stopBtn = document.getElementById('stopBtn');
    const statusText = document.getElementById('statusText');
    const progressBar = document.getElementById('progressBar');

    if (this.scrapingJob) {
      startBtn.classList.add('hidden');
      pauseBtn.classList.remove('hidden');
      stopBtn.classList.remove('hidden');
      progressBar.classList.remove('hidden');
      
      statusText.textContent = this.scrapingJob.status === 'paused' ? 'Paused' : 'Running';
    } else {
      startBtn.classList.remove('hidden');
      pauseBtn.classList.add('hidden');
      stopBtn.classList.add('hidden');
      progressBar.classList.add('hidden');
      
      statusText.textContent = 'Ready';
    }
  }

  addLogEntry(level, message) {
    const logContainer = document.getElementById('logContainer');
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${level}`;
    
    const time = new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit' 
    });
    
    logEntry.innerHTML = `
      <span class="log-time">${time}</span>
      <span class="log-message">${message}</span>
    `;
    
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
    
    // Keep only last 100 entries
    const entries = logContainer.querySelectorAll('.log-entry');
    if (entries.length > 100) {
      entries[0].remove();
    }
  }

  clearLog() {
    const logContainer = document.getElementById('logContainer');
    logContainer.innerHTML = `
      <div class="log-entry info">
        <span class="log-time">Ready</span>
        <span class="log-message">Log cleared</span>
      </div>
    `;
  }

  updateResultsDisplay() {
    const resultsBody = document.getElementById('resultsBody');
    
    if (this.results.length === 0) {
      resultsBody.innerHTML = `
        <div class="empty-state">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="11" cy="11" r="8"/>
            <path d="M21 21l-4.35-4.35"/>
          </svg>
          <p>No results yet</p>
          <p class="empty-subtext">Start scraping to see results here</p>
        </div>
      `;
      return;
    }

    resultsBody.innerHTML = '';
    
    this.results.forEach(result => {
      const row = document.createElement('div');
      row.className = 'table-row';
      
      const statusClass = result.http_status === 200 ? 'status-success' : 'status-error';
      
      row.innerHTML = `
        <div class="table-cell" title="${result.domain}">${result.domain}</div>
        <div class="table-cell" title="${result.email}">${result.email}</div>
        <div class="table-cell" title="${result.source_url}">${this.truncateUrl(result.source_url)}</div>
        <div class="table-cell">
          <span class="status-badge ${statusClass}">${result.http_status}</span>
        </div>
      `;
      
      resultsBody.appendChild(row);
    });
  }

  truncateUrl(url, maxLength = 30) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  updateResultsStats(data) {
    document.getElementById('totalEmails').textContent = data.totalEmails || this.results.length;
    document.getElementById('uniqueDomains').textContent = data.uniqueDomains || this.getUniqueDomains();
    document.getElementById('successRate').textContent = `${data.successRate || this.calculateSuccessRate()}%`;
  }

  getUniqueDomains() {
    const domains = new Set(this.results.map(r => r.domain));
    return domains.size;
  }

  calculateSuccessRate() {
    if (!this.scrapingJob || this.scrapingJob.totalUrls === 0) return 0;
    return Math.round((this.scrapingJob.processedUrls / this.scrapingJob.totalUrls) * 100);
  }

  async exportResults(format) {
    if (this.results.length === 0) {
      this.showError('No results to export');
      return;
    }

    try {
      let content, filename, mimeType;

      if (format === 'csv') {
        content = this.generateCSV();
        filename = `email_results_${this.getTimestamp()}.csv`;
        mimeType = 'text/csv';
      } else {
        content = JSON.stringify(this.results, null, 2);
        filename = `email_results_${this.getTimestamp()}.json`;
        mimeType = 'application/json';
      }

      // Create download
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);

      chrome.downloads.download({
        url: url,
        filename: filename,
        saveAs: true
      });

      this.addLogEntry('success', `Exported ${this.results.length} results as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Export error:', error);
      this.showError('Failed to export results');
    }
  }

  generateCSV() {
    const headers = ['domain', 'email', 'source_url', 'found_at', 'http_status', 'user_agent'];
    const rows = [headers.join(',')];

    this.results.forEach(result => {
      const row = headers.map(header => {
        const value = result[header] || '';
        // Escape quotes and wrap in quotes if contains comma
        return value.includes(',') ? `"${value.replace(/"/g, '""')}"` : value;
      });
      rows.push(row.join(','));
    });

    return rows.join('\n');
  }

  getTimestamp() {
    return new Date().toISOString().slice(0, 19).replace(/[:-]/g, '');
  }

  async copyResults() {
    if (this.results.length === 0) {
      this.showError('No results to copy');
      return;
    }

    try {
      const emails = this.results.map(r => r.email).join('\n');
      await navigator.clipboard.writeText(emails);
      this.addLogEntry('success', `Copied ${this.results.length} emails to clipboard`);
    } catch (error) {
      console.error('Copy error:', error);
      this.showError('Failed to copy results');
    }
  }

  updateUI() {
    // Show/hide sections based on auth status
    const authSection = document.getElementById('authSection');
    const uploadSection = document.getElementById('uploadSection');
    const configSection = document.getElementById('configSection');
    const controlSection = document.getElementById('controlSection');
    const logSection = document.getElementById('logSection');
    const resultsSection = document.getElementById('resultsSection');

    if (this.isAuthenticated) {
      authSection.classList.remove('hidden');
      uploadSection.classList.remove('hidden');
      configSection.classList.remove('hidden');
      controlSection.classList.remove('hidden');
      logSection.classList.remove('hidden');
      resultsSection.classList.remove('hidden');

      // Show user info
      document.getElementById('loginForm').classList.add('hidden');
      document.getElementById('userInfo').classList.remove('hidden');
      document.getElementById('userEmail').textContent = this.currentUser?.email || '';
      document.getElementById('userPlan').textContent = this.currentUser?.plan || 'Free';
    } else {
      authSection.classList.remove('hidden');
      uploadSection.classList.add('hidden');
      configSection.classList.add('hidden');
      controlSection.classList.add('hidden');
      logSection.classList.add('hidden');
      resultsSection.classList.add('hidden');

      // Show login form
      document.getElementById('loginForm').classList.remove('hidden');
      document.getElementById('userInfo').classList.add('hidden');
    }

    // Update config inputs
    if (this.config) {
      document.getElementById('concurrentInput').value = this.config.concurrent;
      document.getElementById('perDomainInput').value = this.config.perDomain;
      document.getElementById('delayMinInput').value = this.config.delayMin;
      document.getElementById('delayMaxInput').value = this.config.delayMax;
      document.getElementById('timeoutInput').value = this.config.timeout;
      document.getElementById('retriesInput').value = this.config.retries;
      document.getElementById('respectRobots').checked = this.config.respectRobots;
    }
  }

  showError(message) {
    // Simple error display - could be enhanced with a proper toast system
    this.addLogEntry('error', message);
    console.error(message);
  }
}

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new EmailScraperUI();
});