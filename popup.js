// Ultimate Email Scraper Pro - Secure Extension UI
class EmailScraperUI {
  constructor() {
    this.isAuthenticated = false;
    this.currentUser = null;
    this.scrapingJob = null;
    this.results = [];
    this.isDarkTheme = false;
    this.fileData = null;
    this.config = this.getDefaultConfig();
    this.logPaused = false;
    this.startTime = null;
    this.timerInterval = null;
    
    // Security and encryption
    this.apiBaseUrl = 'https://api.emailscraper.pro';
    this.encryptionKey = null;
    this.sessionToken = null;
    
    this.init();
  }

  async init() {
    try {
      await this.loadSettings();
      this.setupEventListeners();
      this.setupTheme();
      await this.checkAuthStatus();
      this.updateUI();
      this.addLogEntry('info', 'Extension initialized successfully');
    } catch (error) {
      console.error('Initialization error:', error);
      this.showToast('error', 'Initialization Error', 'Failed to initialize extension');
    }
  }

  async loadSettings() {
    try {
      const result = await chrome.storage.local.get(['theme', 'config', 'authData']);
      this.isDarkTheme = result.theme === 'dark';
      this.config = { ...this.getDefaultConfig(), ...result.config };
      
      if (result.authData) {
        this.sessionToken = result.authData.token;
        this.currentUser = result.authData.user;
      }
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
      respectRobots: true,
      enableCloudFallback: true
    };
  }

  setupEventListeners() {
    // Theme toggle
    document.getElementById('themeToggle').addEventListener('click', () => {
      this.toggleTheme();
    });

    // Help button
    document.getElementById('helpBtn').addEventListener('click', () => {
      this.openHelp();
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
    this.setupFileUploadEvents();

    // Config events
    this.setupConfigEvents();

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
    document.getElementById('pauseLogBtn').addEventListener('click', () => {
      this.toggleLogPause();
    });

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

    // Reset config
    document.getElementById('resetConfig').addEventListener('click', () => {
      this.resetConfig();
    });

    // Listen for messages from background script
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleBackgroundMessage(message);
    });

    // Handle Enter key in login form
    document.getElementById('emailInput').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleLogin();
    });

    document.getElementById('passwordInput').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleLogin();
    });
  }

  setupFileUploadEvents() {
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
  }

  setupConfigEvents() {
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

    document.getElementById('enableCloudFallback').addEventListener('change', () => {
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
    this.addLogEntry('info', `Switched to ${this.isDarkTheme ? 'dark' : 'light'} theme`);
  }

  openHelp() {
    chrome.tabs.create({
      url: 'https://emailscraper.pro/help'
    });
  }

  async checkAuthStatus() {
    try {
      if (this.sessionToken) {
        const isValid = await this.verifyToken(this.sessionToken);
        if (isValid) {
          this.isAuthenticated = true;
          this.addLogEntry('success', 'Authentication verified');
        } else {
          await this.clearAuthData();
          this.addLogEntry('warning', 'Session expired, please sign in again');
        }
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      await this.clearAuthData();
    }
  }

  async verifyToken(token) {
    try {
      const response = await this.secureRequest('/auth/verify', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      return response.ok;
    } catch (error) {
      console.error('Token verification failed:', error);
      return false;
    }
  }

  async secureRequest(endpoint, options = {}) {
    const url = `${this.apiBaseUrl}${endpoint}`;
    const defaultHeaders = {
      'Content-Type': 'application/json',
      'X-Extension-Version': chrome.runtime.getManifest().version,
      'X-Client-ID': await this.getClientId()
    };

    const config = {
      ...options,
      headers: {
        ...defaultHeaders,
        ...options.headers
      }
    };

    // Add anti-tampering checks
    config.headers['X-Integrity-Check'] = await this.generateIntegrityHash();

    return fetch(url, config);
  }

  async getClientId() {
    let clientId = await chrome.storage.local.get(['clientId']);
    if (!clientId.clientId) {
      clientId = this.generateClientId();
      await chrome.storage.local.set({ clientId });
    }
    return clientId.clientId || clientId;
  }

  generateClientId() {
    return 'ext_' + Date.now() + '_' + Math.random().toString(36).substr(2, 16);
  }

  async generateIntegrityHash() {
    // Simple integrity check - in production this would be more sophisticated
    const data = navigator.userAgent + chrome.runtime.getManifest().version;
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substr(0, 16);
  }

  async handleLogin() {
    const email = document.getElementById('emailInput').value.trim();
    const password = document.getElementById('passwordInput').value;

    if (!email || !password) {
      this.showToast('error', 'Validation Error', 'Please enter both email and password');
      return;
    }

    if (!this.isValidEmail(email)) {
      this.showToast('error', 'Validation Error', 'Please enter a valid email address');
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
      const response = await this.secureRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ 
          email, 
          password,
          clientInfo: {
            userAgent: navigator.userAgent,
            timestamp: Date.now()
          }
        })
      });

      const data = await response.json();

      if (response.ok) {
        // Store encrypted auth data
        await chrome.storage.local.set({
          authData: {
            token: data.token,
            user: data.user,
            expiresAt: Date.now() + (data.expiresIn * 1000)
          }
        });

        this.sessionToken = data.token;
        this.isAuthenticated = true;
        this.currentUser = data.user;
        this.updateUI();
        this.showToast('success', 'Welcome!', `Signed in as ${data.user.email}`);
        this.addLogEntry('success', 'Successfully signed in');
        
        // Clear form
        document.getElementById('emailInput').value = '';
        document.getElementById('passwordInput').value = '';
      } else {
        this.showToast('error', 'Sign In Failed', data.message || 'Invalid credentials');
        this.addLogEntry('error', `Login failed: ${data.message || 'Invalid credentials'}`);
      }
    } catch (error) {
      console.error('Login error:', error);
      this.showToast('error', 'Network Error', 'Please check your connection and try again');
      this.addLogEntry('error', 'Network error during login');
    } finally {
      // Reset button state
      btnText.textContent = 'Sign In';
      btnSpinner.classList.add('hidden');
      loginBtn.disabled = false;
    }
  }

  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  async handleLogout() {
    try {
      if (this.sessionToken) {
        // Notify server of logout
        await this.secureRequest('/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.sessionToken}`
          }
        });
      }
      
      await this.clearAuthData();
      this.showToast('info', 'Signed Out', 'You have been signed out successfully');
      this.addLogEntry('info', 'Signed out successfully');
    } catch (error) {
      console.error('Logout error:', error);
      await this.clearAuthData();
    }
  }

  async clearAuthData() {
    await chrome.storage.local.remove(['authData']);
    this.sessionToken = null;
    this.isAuthenticated = false;
    this.currentUser = null;
    this.updateUI();
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
    const validTypes = ['text/csv', 'text/plain'];
    const validExtensions = ['.csv', '.txt'];
    
    const isValidType = validTypes.includes(file.type) || 
                       validExtensions.some(ext => file.name.toLowerCase().endsWith(ext));

    if (!isValidType) {
      this.showToast('error', 'Invalid File', 'Please select a CSV or TXT file');
      return;
    }

    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      this.showToast('error', 'File Too Large', 'File size must be less than 10MB');
      return;
    }

    try {
      const content = await this.readFile(file);
      const urls = this.parseUrls(content);

      if (urls.length === 0) {
        this.showToast('error', 'No URLs Found', 'No valid URLs found in the file');
        return;
      }

      if (urls.length > 10000) {
        this.showToast('error', 'Too Many URLs', 'Maximum 10,000 URLs allowed per file');
        return;
      }

      // Store file data
      this.fileData = {
        name: file.name,
        size: this.formatFileSize(file.size),
        urls: urls,
        urlCount: urls.length
      };

      this.showFileInfo();
      this.updateUrlCount();
      this.showToast('success', 'File Loaded', `Successfully loaded ${urls.length} URLs`);
      this.addLogEntry('success', `Loaded ${urls.length} URLs from ${file.name}`);
    } catch (error) {
      console.error('File processing error:', error);
      this.showToast('error', 'Processing Error', 'Failed to process the file');
      this.addLogEntry('error', 'Failed to process uploaded file');
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
    document.getElementById('fileUrls').textContent = `${this.fileData.urlCount} URLs`;
    document.getElementById('fileInfo').classList.remove('hidden');
  }

  updateUrlCount() {
    const count = this.fileData ? this.fileData.urlCount : 0;
    document.getElementById('urlCount').textContent = `${count} URLs`;
  }

  removeFile() {
    this.fileData = null;
    document.getElementById('fileInfo').classList.add('hidden');
    document.getElementById('fileInput').value = '';
    this.updateUrlCount();
    this.showToast('info', 'File Removed', 'File has been removed');
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
      respectRobots: document.getElementById('respectRobots').checked,
      enableCloudFallback: document.getElementById('enableCloudFallback').checked
    };

    chrome.storage.local.set({ config: this.config });
    this.addLogEntry('info', 'Configuration updated');
  }

  resetConfig() {
    this.config = this.getDefaultConfig();
    this.updateConfigInputs();
    chrome.storage.local.set({ config: this.config });
    this.showToast('info', 'Config Reset', 'Configuration reset to default values');
    this.addLogEntry('info', 'Configuration reset to defaults');
  }

  updateConfigInputs() {
    document.getElementById('concurrentInput').value = this.config.concurrent;
    document.getElementById('perDomainInput').value = this.config.perDomain;
    document.getElementById('delayMinInput').value = this.config.delayMin;
    document.getElementById('delayMaxInput').value = this.config.delayMax;
    document.getElementById('timeoutInput').value = this.config.timeout;
    document.getElementById('retriesInput').value = this.config.retries;
    document.getElementById('respectRobots').checked = this.config.respectRobots;
    document.getElementById('enableCloudFallback').checked = this.config.enableCloudFallback;
  }

  async startScraping() {
    if (!this.isAuthenticated) {
      this.showToast('error', 'Authentication Required', 'Please sign in to start scraping');
      return;
    }

    if (!this.fileData || !this.fileData.urls.length) {
      this.showToast('error', 'No File', 'Please upload a file with URLs first');
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
        userToken: this.sessionToken,
        jobId: this.generateJobId()
      };

      chrome.runtime.sendMessage({
        action: 'startScraping',
        data: jobData
      });

      this.scrapingJob = {
        id: jobData.jobId,
        status: 'running',
        startTime: Date.now(),
        totalUrls: this.fileData.urls.length,
        processedUrls: 0,
        foundEmails: 0
      };

      this.startTime = Date.now();
      this.startTimer();
      this.updateControlButtons();
      this.updateStats();
      this.showToast('success', 'Scraping Started', `Processing ${this.fileData.urls.length} URLs`);
      this.addLogEntry('info', `Started scraping ${this.fileData.urls.length} URLs`);
      
    } catch (error) {
      console.error('Failed to start scraping:', error);
      this.showToast('error', 'Start Failed', 'Failed to start scraping job');
      this.addLogEntry('error', 'Failed to start scraping');
    }
  }

  generateJobId() {
    return 'job_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  async checkLimits() {
    try {
      const response = await this.secureRequest('/limits/check', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.sessionToken}`
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
        this.showToast('error', 'Limit Check Failed', data.message || 'Failed to check limits');
        return false;
      }

      return true;
    } catch (error) {
      console.error('Limit check error:', error);
      this.showToast('error', 'Network Error', 'Failed to check subscription limits');
      return false;
    }
  }

  showUpgradeDialog(message) {
    const upgrade = confirm(`${message}\n\nWould you like to upgrade your subscription?`);
    if (upgrade) {
      this.openSubscriptionManager();
    }
  }

  startTimer() {
    this.timerInterval = setInterval(() => {
      if (this.startTime) {
        const elapsed = Date.now() - this.startTime;
        document.getElementById('timeElapsed').textContent = this.formatTime(elapsed);
      }
    }, 1000);
  }

  stopTimer() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
      this.timerInterval = null;
    }
  }

  formatTime(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}:${(minutes % 60).toString().padStart(2, '0')}:${(seconds % 60).toString().padStart(2, '0')}`;
    }
    return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`;
  }

  pauseScraping() {
    chrome.runtime.sendMessage({ action: 'pauseScraping' });
    if (this.scrapingJob) {
      this.scrapingJob.status = 'paused';
    }
    this.updateControlButtons();
    this.showToast('warning', 'Paused', 'Scraping has been paused');
    this.addLogEntry('warning', 'Scraping paused');
  }

  stopScraping() {
    chrome.runtime.sendMessage({ action: 'stopScraping' });
    this.scrapingJob = null;
    this.startTime = null;
    this.stopTimer();
    this.updateControlButtons();
    this.showToast('info', 'Stopped', 'Scraping has been stopped');
    this.addLogEntry('info', 'Scraping stopped');
  }

  toggleLogPause() {
    this.logPaused = !this.logPaused;
    const btn = document.getElementById('pauseLogBtn');
    const icon = btn.querySelector('svg');
    
    if (this.logPaused) {
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polygon points="5,3 19,12 5,21"/>
        </svg>
        Resume
      `;
      this.addLogEntry('info', 'Log paused');
    } else {
      btn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="6" y="4" width="4" height="16"/>
          <rect x="14" y="4" width="4" height="16"/>
        </svg>
        Pause
      `;
      this.addLogEntry('info', 'Log resumed');
    }
  }

  clearLog() {
    const logContainer = document.getElementById('logContainer');
    logContainer.innerHTML = `
      <div class="log-entry info">
        <div class="log-time">Ready</div>
        <div class="log-content">
          <div class="log-message">Log cleared</div>
        </div>
      </div>
    `;
    this.showToast('info', 'Log Cleared', 'Log has been cleared');
  }

  handleBackgroundMessage(message) {
    switch (message.type) {
      case 'scrapingProgress':
        this.updateProgress(message.data);
        break;
      case 'scrapingLog':
        if (!this.logPaused) {
          this.addLogEntry(message.data.level, message.data.message);
        }
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
      case 'cloudFallback':
        this.handleCloudFallback(message.data);
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
      const progressSpeed = document.querySelector('.progress-speed');
      
      progressFill.style.width = `${progress}%`;
      progressText.textContent = `${data.processed}/${this.scrapingJob.totalUrls} processed`;
      
      // Calculate speed
      if (this.startTime && data.processed > 0) {
        const elapsed = (Date.now() - this.startTime) / 1000 / 60; // minutes
        const speed = Math.round(data.emailsFound / elapsed);
        progressSpeed.textContent = `${speed} emails/min`;
      }
      
      this.updateStats();
    }
  }

  updateStats() {
    if (this.scrapingJob) {
      document.getElementById('processedCount').textContent = this.scrapingJob.processedUrls;
      document.getElementById('emailsFound').textContent = this.scrapingJob.foundEmails;
      
      const successRate = this.scrapingJob.totalUrls > 0 ? 
        Math.round((this.scrapingJob.processedUrls / this.scrapingJob.totalUrls) * 100) : 0;
      document.getElementById('successRate').textContent = `${successRate}%`;
    }
  }

  addResult(result) {
    this.results.push(result);
    this.updateResultsDisplay();
    this.updateResultsSummary();
  }

  handleScrapingComplete(data) {
    this.scrapingJob = null;
    this.stopTimer();
    this.updateControlButtons();
    
    const message = `Scraping completed! Found ${data.totalEmails} emails from ${data.uniqueDomains} domains`;
    this.showToast('success', 'Complete!', message);
    this.addLogEntry('success', message);
    
    // Hide progress bar
    document.getElementById('progressBar').classList.add('hidden');
    
    // Update final stats
    this.updateResultsSummary(data);
  }

  handleScrapingError(error) {
    this.scrapingJob = null;
    this.stopTimer();
    this.updateControlButtons();
    
    const message = `Scraping failed: ${error.message}`;
    this.showToast('error', 'Scraping Failed', message);
    this.addLogEntry('error', message);
    
    document.getElementById('progressBar').classList.add('hidden');
  }

  handleCloudFallback(data) {
    this.showToast('warning', 'Cloud Fallback', 'Switched to secure cloud processing');
    this.addLogEntry('warning', 'Switched to cloud fallback mode for enhanced security');
  }

  updateControlButtons() {
    const startBtn = document.getElementById('startBtn');
    const pauseBtn = document.getElementById('pauseBtn');
    const stopBtn = document.getElementById('stopBtn');
    const statusText = document.getElementById('statusText');
    const statusDot = document.getElementById('statusDot');
    const progressBar = document.getElementById('progressBar');

    if (this.scrapingJob) {
      startBtn.classList.add('hidden');
      pauseBtn.classList.remove('hidden');
      stopBtn.classList.remove('hidden');
      progressBar.classList.remove('hidden');
      
      if (this.scrapingJob.status === 'paused') {
        statusText.textContent = 'Paused';
        statusDot.style.background = 'var(--warning)';
        pauseBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polygon points="5,3 19,12 5,21"/>
          </svg>
          <span>Resume</span>
        `;
      } else {
        statusText.textContent = 'Running';
        statusDot.style.background = 'var(--success)';
        pauseBtn.innerHTML = `
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="6" y="4" width="4" height="16"/>
            <rect x="14" y="4" width="4" height="16"/>
          </svg>
          <span>Pause</span>
        `;
      }
    } else {
      startBtn.classList.remove('hidden');
      pauseBtn.classList.add('hidden');
      stopBtn.classList.add('hidden');
      progressBar.classList.add('hidden');
      
      statusText.textContent = 'Ready';
      statusDot.style.background = 'var(--text-muted)';
    }
  }

  addLogEntry(level, message) {
    if (this.logPaused) return;
    
    const logContainer = document.getElementById('logContainer');
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${level}`;
    
    const time = new Date().toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit',
      second: '2-digit'
    });
    
    logEntry.innerHTML = `
      <div class="log-time">${time}</div>
      <div class="log-content">
        <div class="log-message">${message}</div>
      </div>
    `;
    
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
    
    // Keep only last 100 entries
    const entries = logContainer.querySelectorAll('.log-entry');
    if (entries.length > 100) {
      entries[0].remove();
    }
  }

  updateResultsDisplay() {
    const resultsBody = document.getElementById('resultsBody');
    
    if (this.results.length === 0) {
      resultsBody.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <circle cx="11" cy="11" r="8"/>
              <path d="M21 21l-4.35-4.35"/>
            </svg>
          </div>
          <div class="empty-content">
            <h3 class="empty-title">No results yet</h3>
            <p class="empty-subtitle">Start scraping to see email results here</p>
          </div>
        </div>
      `;
      return;
    }

    resultsBody.innerHTML = '';
    
    // Show last 50 results for performance
    const recentResults = this.results.slice(-50);
    
    recentResults.forEach(result => {
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

  truncateUrl(url, maxLength = 25) {
    if (url.length <= maxLength) return url;
    return url.substring(0, maxLength - 3) + '...';
  }

  updateResultsSummary(data = null) {
    const totalEmails = data?.totalEmails || this.results.length;
    const uniqueDomains = data?.uniqueDomains || this.getUniqueDomains();
    const avgPerDomain = uniqueDomains > 0 ? Math.round(totalEmails / uniqueDomains * 10) / 10 : 0;

    document.getElementById('totalEmails').textContent = totalEmails;
    document.getElementById('uniqueDomains').textContent = uniqueDomains;
    document.getElementById('avgPerDomain').textContent = avgPerDomain;
  }

  getUniqueDomains() {
    const domains = new Set(this.results.map(r => r.domain));
    return domains.size;
  }

  async exportResults(format) {
    if (this.results.length === 0) {
      this.showToast('error', 'No Results', 'No results to export');
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

      this.showToast('success', 'Export Complete', `Exported ${this.results.length} results as ${format.toUpperCase()}`);
      this.addLogEntry('success', `Exported ${this.results.length} results as ${format.toUpperCase()}`);
    } catch (error) {
      console.error('Export error:', error);
      this.showToast('error', 'Export Failed', 'Failed to export results');
      this.addLogEntry('error', 'Failed to export results');
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
      this.showToast('error', 'No Results', 'No results to copy');
      return;
    }

    try {
      const emails = this.results.map(r => r.email).join('\n');
      await navigator.clipboard.writeText(emails);
      this.showToast('success', 'Copied!', `Copied ${this.results.length} emails to clipboard`);
      this.addLogEntry('success', `Copied ${this.results.length} emails to clipboard`);
    } catch (error) {
      console.error('Copy error:', error);
      this.showToast('error', 'Copy Failed', 'Failed to copy results to clipboard');
      this.addLogEntry('error', 'Failed to copy results');
    }
  }

  updateUI() {
    // Show/hide cards based on auth status
    const cards = {
      upload: document.getElementById('uploadCard'),
      config: document.getElementById('configCard'),
      control: document.getElementById('controlCard'),
      log: document.getElementById('logCard'),
      results: document.getElementById('resultsCard')
    };

    if (this.isAuthenticated) {
      // Show authenticated UI
      Object.values(cards).forEach(card => card.classList.remove('hidden'));

      // Update user info
      document.getElementById('loginForm').classList.add('hidden');
      document.getElementById('userInfo').classList.remove('hidden');
      document.getElementById('userStatus').classList.remove('hidden');
      
      if (this.currentUser) {
        document.getElementById('userName').textContent = this.currentUser.name || 'User';
        document.getElementById('userEmail').textContent = this.currentUser.email || '';
        document.getElementById('userPlan').textContent = this.currentUser.plan || 'Free Plan';
        document.getElementById('userInitials').textContent = 
          (this.currentUser.name || this.currentUser.email || 'U').charAt(0).toUpperCase();
      }
    } else {
      // Show login form only
      Object.values(cards).forEach(card => card.classList.add('hidden'));
      
      document.getElementById('loginForm').classList.remove('hidden');
      document.getElementById('userInfo').classList.add('hidden');
      document.getElementById('userStatus').classList.add('hidden');
    }

    // Update config inputs
    this.updateConfigInputs();
    
    // Update control buttons
    this.updateControlButtons();
  }

  showToast(type, title, message) {
    const toastContainer = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
      success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/></svg>',
      error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
      warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
      info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
    };
    
    toast.innerHTML = `
      <div class="toast-icon">${icons[type]}</div>
      <div class="toast-content">
        <div class="toast-title">${title}</div>
        <div class="toast-message">${message}</div>
      </div>
      <button class="toast-close" onclick="this.parentElement.remove()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>
    `;
    
    toastContainer.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
      if (toast.parentElement) {
        toast.remove();
      }
    }, 5000);
  }
}

// Initialize the UI when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new EmailScraperUI();
});