// PII Detection & Encryption Tool - Enhanced Security Version
// WARNING: This tool is for demonstration purposes only.
// For production use, implement server-side processing and proper encryption.
//
// ENHANCED WITH PRODUCTION-GRADE PATTERNS:
// - Luhn algorithm validation for credit cards (reduces false positives)
// - IPv4/IPv6 address detection with proper validation
// - SSN pattern excludes invalid prefixes (000, 666, 9xx)
// - Improved phone number patterns for US numbers
// - Robust email and ZIP code detection
// - JSON structure exclusion to prevent field name detection

/**
 * PII Detection and Encryption Tool
 * Detects various types of personally identifiable information in text
 * and provides multiple processing options including masking, hashing, and encryption.
 * 
 * @class PIITool
 */
class PIITool {
    /**
     * Initialize the PII Tool with patterns and state
     */
    constructor() {
        /** @type {Object.<string, {pattern: RegExp, name: string, color: string, priority: number}>} */
        this.piiPatterns = {
            email: {
                pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
                name: "Email Address",
                color: "#FF6B6B",
                priority: 1
            },
            ssn: {
                pattern: /\b(?!000|666|9\d\d)\d{3}[-\s.]?(?!00)\d{2}[-\s.]?(?!0000)\d{4}\b/g,
                name: "Social Security Number",
                color: "#45B7D1",
                priority: 2
            },
            phone: {
                pattern: /\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
                name: "Phone Number",
                color: "#4ECDC4",
                priority: 3
            },
            creditCard: {
                pattern: /\b(?:\d[ -]*?){13,19}\b/g,
                name: "Credit Card",
                color: "#F9CA24",
                priority: 4,
                requiresLuhn: true
            },
            url: {
                pattern: /https?:\/\/(?:[-\w.])+(?:[:\d]+)?(?:\/(?:[\w\/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?/g,
                name: "URL",
                color: "#FD79A8",
                priority: 5
            },
            ipv4Address: {
                pattern: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
                name: "IPv4 Address",
                color: "#A55EEA",
                priority: 6
            },
            ipv6Address: {
                pattern: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
                name: "IPv6 Address",
                color: "#A0522D",
                priority: 7
            },
            taxId: {
                pattern: /\b\d{2}-\d{7}\b/g,
                name: "Tax ID",
                color: "#6C5CE7",
                priority: 8
            },
            employeeId: {
                pattern: /\b(?:EMP|STU|PAT|CS|GOV)-\d{4}-\d{3,5}\b/g,
                name: "ID Number",
                color: "#A0E7E5",
                priority: 9
            },
            alphanumericId: {
                pattern: /\b[A-Z]{2,4}-\d{5,10}\b/g,
                name: "Alphanumeric ID",
                color: "#00B894",
                priority: 10
            },
            accountNumber: {
                pattern: /\b[A-Z0-9]{8,16}\b/g,
                name: "Account Number",
                color: "#FF9F43",
                priority: 11
            },
            routingNumber: {
                pattern: /\b\d{9}\b/g,
                name: "Routing Number",
                color: "#FDCB6E",
                priority: 11
            },
            name: {
                pattern: /\b(?:Dr\.?\s+|Mr\.?\s+|Mrs\.?\s+|Ms\.?\s+|Prof\.?\s+)[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})+(?:\s+[A-Z][a-z]{2,})*(?:\s+(?:Jr\.?|Sr\.?|III?|IV))?\b/g,
                name: "Full Name",
                color: "#FF7675",
                priority: 13
            },
            firstName: {
                pattern: /\b[A-Z][a-z]{2,15}\b/g,
                name: "First Name",
                color: "#FF6B9D",
                priority: 12,
                contextAware: true
            },
            companyName: {
                pattern: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\s+(?:LLC|Inc|Corp|Corporation|Company|Co|Ltd|Limited|University|Institute|College|Hospital|Medical|Center|Health|Bank|Insurance|Group|Board|Technology|Academy|School)\b/g,
                name: "Organization Name",
                color: "#74B9FF",
                priority: 14
            },
            address: {
                pattern: /\b\d+\s+[A-Za-z0-9\s,]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Circle|Cir|Plaza|Court|Ct|Highway|Hwy)\b/g,
                name: "Street Address",
                color: "#00B894",
                priority: 15
            },
            date: {
                pattern: /\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4})\b/gi,
                name: "Date",
                color: "#FDCB6E",
                priority: 16
            },
            zipCode: {
                pattern: /\b\d{5}(?:-\d{4})?\b/g,
                name: "US ZIP Code",
                color: "#26DE81",
                priority: 17
            },
            extension: {
                pattern: /\bextension\s+\d{3,4}\b/gi,
                name: "Extension",
                color: "#B2BEC3",
                priority: 18
            },

            cityState: {
                pattern: /\b[A-Z][a-z]{4,},\s*[A-Z][a-z]{4,},\s*USA\b/g,
                name: "City/State",
                color: "#C44569",
                priority: 20
            },
            passport: {
                pattern: /\b[A-Z]{2,3}\d{8,9}\b/g,
                name: "Passport Number",
                color: "#6C5CE7",
                priority: 21
            },
            macAddress: {
                pattern: /\b[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\b/g,
                name: "MAC Address",
                color: "#A0E7E5",
                priority: 22
            },
            username: {
                pattern: /\b[a-z][a-z0-9_\.]{6,25}(?:\.[a-z]{2,15})?\b/g,
                name: "Username",
                color: "#FD79A8",
                priority: 23
            },
            medicalLicense: {
                pattern: /\b[A-Z]{2}-[A-Z]{2}-\d{6,12}\b/g,
                name: "Medical License",
                color: "#E84393",
                priority: 24
            },
            deaNumber: {
                pattern: /\b[A-Z]{2}\d{7}\b/g,
                name: "DEA Number",
                color: "#00B894",
                priority: 25
            },
            deviceId: {
                pattern: /\b[A-Z]{3}-[A-Z0-9]{3,12}[A-Z0-9]{3,12}\b/g,
                name: "Device ID",
                color: "#FDCB6E",
                priority: 26
            },
            fingerprint: {
                pattern: /\b[A-Z]{2}-\d{12,18}\b/g,
                name: "Biometric ID",
                color: "#E17055",
                priority: 27
            },

            licenseNumber: {
                pattern: /\b[A-Z]{2}-[A-Z]{2,3}-[A-Z0-9]{6,12}\b/g,
                name: "License Number",
                color: "#A29BFE",
                priority: 29
            },

            apartment: {
                pattern: /\b(?:Apt|Suite|Unit|Apartment|Room)\s+[A-Z0-9]{1,5}\b/gi,
                name: "Apartment/Suite",
                color: "#74B9FF",
                priority: 34
            },
            trackingNumber: {
                pattern: /\b1Z[A-Z0-9]{16}\b|\b[A-Z0-9]{10,30}\b/g,
                name: "Tracking Number",
                color: "#8E44AD",
                priority: 35
            },
            orderID: {
                pattern: /\b(?:ORD|SHOP|CUST|RET|SHIP|TXN|WH)[-_][A-Z0-9]{4,20}\b/g,
                name: "Order/Transaction ID",
                color: "#E67E22",
                priority: 36
            },
            poBox: {
                pattern: /\bPO\s+Box\s+\d{3,6}\b/gi,
                name: "PO Box",
                color: "#E17055",
                priority: 35
            }
        };

        /** @type {Object.<string, Object>} Detected PII items by type */
        this.detectedPII = {};
        
        /** @type {Set<string>} Enabled PII types for processing */
        this.enabledTypes = new Set(Object.keys(this.piiPatterns));
        
        /** @type {string} Last processed text output */
        this.processedText = '';
        
        /** @type {Object} Processing statistics and metadata */
        this.processedData = {};
        
        /** @type {CryptoKey|null} Encryption key for AES operations */
        this.encryptionKey = null;
        
        // Initialize the application
        this.init();
    }

    /**
     * Initialize the tool by binding events and setting up UI
     */
    init() {
        console.log('Initializing PII Tool...');
        this.bindEvents();
        this.createPIIToggles();
        this.loadSampleText();
        
        // Hide loading overlay after initialization
        this.hideLoading();
        console.log('PII Tool initialized successfully');
    }

    /**
     * Bind event listeners to DOM elements
     */
    bindEvents() {
        /** @type {Object.<string, HTMLElement|null>} */
        const elements = {
            inputText: document.getElementById('inputText'),
            analyzeBtn: document.getElementById('analyzeBtn'),
            clearBtn: document.getElementById('clearBtn'),
            encryptionMethod: document.getElementById('encryptionMethod'),
            processBtn: document.getElementById('processBtn'),
            copyBtn: document.getElementById('copyBtn'),
            downloadBtn: document.getElementById('downloadBtn')
        };

        if (elements.analyzeBtn) {
            elements.analyzeBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.analyzeText();
            });
        }

        if (elements.clearBtn) {
            elements.clearBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.clearAll();
            });
        }

        // Select All / Unselect All buttons
        const selectAllBtn = document.getElementById('selectAllBtn');
        const unselectAllBtn = document.getElementById('unselectAllBtn');

        if (selectAllBtn) {
            selectAllBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.selectAllPIITypes();
            });
        }

        if (unselectAllBtn) {
            unselectAllBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.unselectAllPIITypes();
            });
        }

        if (elements.encryptionMethod) {
            elements.encryptionMethod.addEventListener('change', () => {
                this.handleEncryptionMethodChange();
            });
        }

        if (elements.processBtn) {
            elements.processBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.processText();
            });
        }

        if (elements.copyBtn) {
            elements.copyBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.copyToClipboard();
            });
        }

        if (elements.downloadBtn) {
            elements.downloadBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.downloadText();
            });
        }

        console.log('Event bindings completed');
    }

    /**
     * Load sample text for demonstration
     */
    loadSampleText() {
        const inputText = document.getElementById('inputText');
        if (inputText) {
            const sampleText = `{
  "order": {
    "order_number": "ORD-2024-789123",
    "order_status": "shipped",
    "customer": {
      "customer_id": "CUST_987654321",
      "email": "john.doe@email.com",
      "first_name": "John",
      "last_name": "Doe",
      "phone": "+1-555-123-4567"
    },
    "billing_address": {
      "first_name": "John",
      "last_name": "Doe",
      "address_line_1": "123 Main Street",
      "address_line_2": "Apt 4B",
      "city": "New York",
      "state": "NY",
      "postal_code": "10001"
    },
    "items": [
      {
        "name": "Classic Blue Cotton Shirt",
        "color": "Navy Blue",
        "size": "Medium"
      }
    ],
    "shipments": [
      {
        "tracking_number": "1Z999AA1234567890",
        "shipment_status": "in_transit"
      }
    ]
  }
}`;
            inputText.value = sampleText;
            console.log('Sample text loaded');
        }
    }

    /**
     * Create toggle switches for PII types
     */
    createPIIToggles() {
        /** @type {HTMLElement|null} */
        const togglesContainer = document.getElementById('piiToggles');
        if (!togglesContainer) {
            console.warn('Toggle container not found');
            return;
        }
        
        togglesContainer.innerHTML = '';

        Object.entries(this.piiPatterns).forEach(([key, pii]) => {
            const toggleItem = document.createElement('div');
            toggleItem.className = 'toggle-item';
            toggleItem.innerHTML = `
                <div class="toggle-info">
                    <div class="toggle-color" style="background-color: ${pii.color}"></div>
                    <span class="toggle-label">${pii.name}</span>
                </div>
                <div class="toggle-switch active" 
                     data-type="${key}" 
                     role="switch" 
                     aria-checked="true" 
                     aria-label="Toggle ${pii.name} detection"
                     tabindex="0"></div>
            `;

            const toggle = toggleItem.querySelector('.toggle-switch');
            toggle.addEventListener('click', (e) => {
                e.preventDefault();
                this.togglePIIType(key, toggle);
            });
            
            // Add keyboard support
            toggle.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    this.togglePIIType(key, toggle);
                }
            });
            
            togglesContainer.appendChild(toggleItem);
        });
        
        console.log('PII toggles created');
    }

    /**
     * Toggle PII type enabled/disabled state
     * @param {string} type - PII type identifier
     * @param {HTMLElement} toggleElement - Toggle DOM element
     */
    togglePIIType(type, toggleElement) {
        if (this.enabledTypes.has(type)) {
            this.enabledTypes.delete(type);
            toggleElement.classList.remove('active');
            toggleElement.setAttribute('aria-checked', 'false');
        } else {
            this.enabledTypes.add(type);
            toggleElement.classList.add('active');
            toggleElement.setAttribute('aria-checked', 'true');
        }
        console.log(`Toggled ${type}:`, this.enabledTypes.has(type));
    }

    /**
     * Select all PII types for processing
     */
    selectAllPIITypes() {
        console.log('Selecting all PII types...');
        
        // Enable all PII types
        Object.keys(this.piiPatterns).forEach(type => {
            this.enabledTypes.add(type);
        });

        // Update all toggle UI elements
        this.updateAllToggles();
        
        this.showToast('✅ All PII types selected for processing', 'success');
    }

    /**
     * Unselect all PII types from processing
     */
    unselectAllPIITypes() {
        console.log('Unselecting all PII types...');
        
        // Disable all PII types
        this.enabledTypes.clear();

        // Update all toggle UI elements
        this.updateAllToggles();
        
        this.showToast('❌ All PII types unselected', 'warning');
    }

    /**
     * Update all toggle UI elements to match the enabled state
     */
    updateAllToggles() {
        Object.keys(this.piiPatterns).forEach(type => {
            const toggle = document.querySelector(`[data-type="${type}"]`);
            if (toggle) {
                const isEnabled = this.enabledTypes.has(type);
                
                // Update visual state
                if (isEnabled) {
                    toggle.classList.add('active');
                    toggle.setAttribute('aria-checked', 'true');
                } else {
                    toggle.classList.remove('active');
                    toggle.setAttribute('aria-checked', 'false');
                }
                
                // Update screen reader announcement
                const statusText = isEnabled ? 'enabled' : 'disabled';
                console.log(`Updated ${type} toggle: ${statusText}`);
            } else {
                console.warn(`Toggle not found for type: ${type}`);
            }
        });
    }

    /**
     * Analyze input text for PII patterns
     */
    async analyzeText() {
        console.log('Starting text analysis...');
        
        /** @type {string} */
        const inputText = document.getElementById('inputText')?.value?.trim();
        if (!inputText) {
            this.showToast('❌ Please enter some text to analyze. You can use the sample text provided.', 'error');
            return;
        }

        // Dynamic performance warnings based on text length
        if (inputText.length > 100000) {
            this.showToast('⚠️ Large text detected. Processing may take longer for texts over 100K characters.', 'warning');
        }

        this.showLoading();
        
        // Reset detection data
        this.detectedPII = {};
        let totalCount = 0;

        try {
            // Use chunked processing for large texts
            if (inputText.length > 50000) {
                await this.processLargeText(inputText);
            } else {
                // Standard processing for smaller texts
                this.processStandardText(inputText);
            }
            
        } catch (error) {
            console.error('Analysis error:', error);
            this.hideLoading();
            this.showToast('❌ Error analyzing text. Please check your input and try again.', 'error');
        }
    }

    /**
     * Process standard-sized text (under 50K characters)
     * @param {string} inputText - Text to analyze
     */
    processStandardText(inputText) {
        let totalCount = 0;

        // Sort patterns by priority (lower priority number = higher precedence)
        const sortedPatterns = Object.entries(this.piiPatterns).sort((a, b) => {
            return (a[1].priority || 99) - (b[1].priority || 99);
        });

        // Detect PII for each type in priority order
        sortedPatterns.forEach(([key, pii]) => {
            const matches = [];
            let match;
            const regex = new RegExp(pii.pattern.source, pii.pattern.flags);
            
            while ((match = regex.exec(inputText)) !== null) {
                // Skip if this looks like a JSON key (surrounded by quotes and followed by colon)
                const beforeMatch = inputText.substring(Math.max(0, match.index - 10), match.index);
                const afterMatch = inputText.substring(match.index + match[0].length, match.index + match[0].length + 10);
                
                // Skip JSON keys and structure
                if (this.isJsonStructure(beforeMatch, match[0], afterMatch)) {
                    console.log(`Skipping JSON structure in standard: "${match[0]}" (before: "${beforeMatch.slice(-10)}", after: "${afterMatch.slice(0, 10)}")`);
                    if (!regex.global) break;
                    continue;
                }
                
                // Context-aware filtering for names (avoid common words/product terms)
                if (pii.contextAware && this.isCommonWord(match[0])) {
                    console.log(`Skipping common word: "${match[0]}"`);
                    if (!regex.global) break;
                    continue;
                }
                
                // Special validation for credit cards
                if (key === 'creditCard' && pii.requiresLuhn) {
                    if (this.luhnCheck(match[0])) {
                        matches.push({
                            text: match[0],
                            index: match.index
                        });
                    } else {
                        console.log(`Rejected credit card (Luhn failed): "${match[0]}"`);
                    }
                } else {
                    matches.push({
                        text: match[0],
                        index: match.index
                    });
                }
                // Prevent infinite loop with global regex
                if (!regex.global) break;
            }
            
            if (matches.length > 0) {
                this.detectedPII[key] = {
                    matches: matches,
                    count: matches.length,
                    ...pii
                };
                totalCount += matches.length;
            }
        });

        console.log(`Found ${totalCount} PII items:`, this.detectedPII);
        
        setTimeout(() => {
            this.displayResults(inputText, totalCount);
            this.hideLoading();
            this.showToast(`Analysis complete! Found ${totalCount} PII items.`, 'success');
        }, 100);
    }

    /**
     * Process large text using chunked approach for better performance
     * @param {string} inputText - Large text to analyze
     */
    async processLargeText(inputText) {
        const chunkSize = 10000; // Process in 10K character chunks
        const overlap = 500; // Overlap to catch PII spanning chunks
        const chunks = [];
        let totalCount = 0;

        // Create chunks with overlap
        for (let i = 0; i < inputText.length; i += chunkSize - overlap) {
            const end = Math.min(i + chunkSize, inputText.length);
            chunks.push({
                text: inputText.slice(i, end),
                offset: i
            });
        }

        console.log(`Processing ${inputText.length} characters in ${chunks.length} chunks...`);

        // Process chunks with progress updates
        for (let i = 0; i < chunks.length; i++) {
            const chunk = chunks[i];
            const progress = Math.round(((i + 1) / chunks.length) * 100);
            
            // Update progress
            this.updateProgress(progress, `Processing chunk ${i + 1} of ${chunks.length}...`);
            
            // Process this chunk
            await this.processChunk(chunk, i === 0); // Only reset on first chunk
            
            // Yield control to prevent UI blocking
            await this.sleep(10);
        }

        // Deduplicate overlapping matches
        this.deduplicateMatches();
        
        // Calculate total count
        totalCount = Object.values(this.detectedPII).reduce((sum, data) => sum + data.count, 0);
        
        console.log(`Large text processing complete! Found ${totalCount} PII items across ${chunks.length} chunks`);
        
        this.displayResults(inputText, totalCount);
        this.hideLoading();
        this.showToast(`✅ Large text analysis complete! Found ${totalCount} PII items in ${chunks.length} chunks.`, 'success');
    }

    /**
     * Process a single chunk of text
     * @param {Object} chunk - Chunk object with text and offset
     * @param {boolean} resetData - Whether to reset detection data
     */
    async processChunk(chunk, resetData = false) {
        if (resetData) {
            this.detectedPII = {};
        }

        // Sort patterns by priority (lower priority number = higher precedence)
        const sortedPatterns = Object.entries(this.piiPatterns).sort((a, b) => {
            return (a[1].priority || 99) - (b[1].priority || 99);
        });

        sortedPatterns.forEach(([key, pii]) => {
            const matches = [];
            let match;
            const regex = new RegExp(pii.pattern.source, pii.pattern.flags);
            
            while ((match = regex.exec(chunk.text)) !== null) {
                // Skip if this looks like a JSON key (surrounded by quotes and followed by colon)
                const beforeMatch = chunk.text.substring(Math.max(0, match.index - 10), match.index);
                const afterMatch = chunk.text.substring(match.index + match[0].length, match.index + match[0].length + 10);
                
                // Skip JSON keys and structure
                if (this.isJsonStructure(beforeMatch, match[0], afterMatch)) {
                    console.log(`Skipping JSON structure in chunk: "${match[0]}" (before: "${beforeMatch.slice(-10)}", after: "${afterMatch.slice(0, 10)}")`);
                    if (!regex.global) break;
                    continue;
                }
                
                // Context-aware filtering for names (avoid common words/product terms)
                if (pii.contextAware && this.isCommonWord(match[0])) {
                    console.log(`Skipping common word: "${match[0]}"`);
                    if (!regex.global) break;
                    continue;
                }
                
                // Special validation for credit cards
                if (key === 'creditCard' && pii.requiresLuhn) {
                    if (this.luhnCheck(match[0])) {
                        matches.push({
                            text: match[0],
                            index: match.index + chunk.offset // Adjust for chunk offset
                        });
                    } else {
                        console.log(`Rejected credit card (Luhn failed): "${match[0]}"`);
                    }
                } else {
                    matches.push({
                        text: match[0],
                        index: match.index + chunk.offset // Adjust for chunk offset
                    });
                }
                // Prevent infinite loop with global regex
                if (!regex.global) break;
            }
            
            if (matches.length > 0) {
                if (!this.detectedPII[key]) {
                    this.detectedPII[key] = {
                        matches: [],
                        count: 0,
                        ...pii
                    };
                }
                
                this.detectedPII[key].matches.push(...matches);
                this.detectedPII[key].count += matches.length;
            }
        });
    }

    /**
     * Remove duplicate matches that may occur in chunk overlaps
     */
    deduplicateMatches() {
        Object.keys(this.detectedPII).forEach(key => {
            const data = this.detectedPII[key];
            const uniqueMatches = [];
            const seen = new Set();
            
            data.matches.forEach(match => {
                const identifier = `${match.index}-${match.text}`;
                if (!seen.has(identifier)) {
                    seen.add(identifier);
                    uniqueMatches.push(match);
                }
            });
            
            data.matches = uniqueMatches;
            data.count = uniqueMatches.length;
        });
    }

    /**
     * Update progress indicator for long operations
     * @param {number} percentage - Progress percentage (0-100)
     * @param {string} message - Progress message
     */
    updateProgress(percentage, message) {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            let progressEl = overlay.querySelector('.progress-info');
            if (!progressEl) {
                progressEl = document.createElement('div');
                progressEl.className = 'progress-info';
                progressEl.innerHTML = `
                    <div class="progress-bar">
                        <div class="progress-fill"></div>
                    </div>
                    <div class="progress-text"></div>
                `;
                overlay.appendChild(progressEl);
            }
            
            const progressFill = progressEl.querySelector('.progress-fill');
            const progressText = progressEl.querySelector('.progress-text');
            
            if (progressFill) progressFill.style.width = `${percentage}%`;
            if (progressText) progressText.textContent = message;
        }
    }

    /**
     * Sleep utility for yielding control during processing
     * @param {number} ms - Milliseconds to sleep
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Validate a credit card number using the Luhn algorithm
     * @param {string} numberStr - Credit card number string
     * @returns {boolean} True if valid according to Luhn algorithm
     */
    luhnCheck(numberStr) {
        // Extract only digits
        const digits = numberStr.replace(/\D/g, '').split('').map(Number);
        
        if (digits.length < 13 || digits.length > 19) {
            return false;
        }
        
        let checksum = 0;
        const parity = digits.length % 2;
        
        for (let i = 0; i < digits.length; i++) {
            let digit = digits[i];
            if (i % 2 === parity) {
                digit *= 2;
                if (digit > 9) {
                    digit -= 9;
                }
            }
            checksum += digit;
        }
        
        return checksum % 10 === 0;
    }

    /**
     * Check if a match appears to be JSON structure that should be skipped
     * @param {string} before - Text before the match
     * @param {string} match - The matched text
     * @param {string} after - Text after the match
     * @returns {boolean} True if this looks like JSON structure
     */
    isJsonStructure(before, match, after) {
        // Skip if this is clearly a JSON key (surrounded by quotes and followed by colon)
        if (before.endsWith('"') && after.startsWith('":')) {
            return true;
        }
        
        // Skip only very specific JSON structure words (be much more conservative)
        const jsonStructureWords = [
            'timestamp', 'data_source', 'purpose', 'records', 'metadata', 
            'test_dataset', 'record_id', 'data_classification', 'contains_pii', 
            'pii_types', 'compliance_notes', 'gdpr_applicable', 'ccpa_applicable', 
            'hipaa_applicable', 'total_records', 'order_number', 'external_order_id',
            'order_date', 'order_status', 'order_total', 'tax_amount', 'shipping_amount',
            'discount_amount', 'customer_id', 'loyalty_member', 'loyalty_tier',
            'billing_address', 'shipping_address', 'address_line_1', 'address_line_2',
            'postal_code', 'country', 'shipments', 'shipment_id', 'tracking_number',
            'carrier', 'carrier_service', 'ship_date', 'estimated_delivery_date',
            'actual_delivery_date', 'shipment_status', 'tracking_url', 'shipped_from',
            'facility_name', 'tracking_events', 'event_date', 'event_type', 'location',
            'description', 'carrier_event_code', 'delivery_instructions', 'signature_required',
            'insurance_value', 'returns', 'return_id', 'return_date', 'return_status',
            'return_reason', 'return_type', 'refund_amount', 'return_shipping_label',
            'notifications', 'order_confirmation_sent', 'shipping_notification_sent',
            'delivery_notification_sent', 'sms_enabled', 'email_enabled', 'push_notifications_enabled',
            'custom_attributes', 'source_channel', 'marketing_campaign', 'gift_order',
            'priority_shipping', 'customer_notes', 'internal_notes', 'payment_info',
            'payment_method', 'card_type', 'last_four', 'payment_status', 'transaction_id',
            'fulfillment_location', 'warehouse_id', 'warehouse_name', 'created_at',
            'updated_at', 'tags', 'api_version', 'request_id', 'retailer_id', 'environment',
            'items', 'sku', 'product_id', 'name', 'description', 'quantity', 'unit_price',
            'total_price', 'category', 'subcategory', 'brand', 'size', 'color', 'weight',
            'dimensions', 'length', 'width', 'height', 'unit', 'image_url', 'product_url',
            'gift_message', 'customization', 'monogram', 'thread_color', 'condition',
            'label_url', 'amount', 'currency', 'value', 'shipped', 'in_transit',
            'delivered', 'pending', 'approved', 'rejected', 'completed', 'processing',
            'canceled', 'returned', 'exchange', 'refund', 'website', 'mobile_app',
            'phone', 'email', 'chat', 'false', 'true', 'inches', 'lbs', 'kg', 'cm',
            'cotton', 'classic', 'premium', 'medium', 'large', 'small', 'blue', 'navy',
            'indigo', 'black', 'white', 'red', 'green', 'front', 'back', 'door',
            'facility', 'package', 'arrived', 'departed', 'wrong', 'size', 'color',
            'style', 'fit', 'button', 'down', 'shirt', 'jeans', 'denim', 'straight',
            'production', 'development', 'staging'
        ];
        
        // Only skip if it's an exact match to structure words AND appears to be a field name
        if (jsonStructureWords.includes(match.toLowerCase()) && 
            before.endsWith('"') && after.startsWith('":')) {
            return true;
        }
        
        return false;
    }

    /**
     * Check if a word is a common English word that shouldn't be considered a name
     * @param {string} word - Word to check
     * @returns {boolean} True if it's a common word to exclude
     */
    isCommonWord(word) {
        const commonWords = [
            // Business terms
            'Visa', 'Card', 'Type', 'Status', 'Date', 'Code', 'Number', 'Amount', 'Total',
            'Order', 'Customer', 'Address', 'Phone', 'Email', 'Payment', 'Shipping',
            'Product', 'Items', 'Description', 'Category', 'Brand', 'Size', 'Color',
            'Weight', 'Value', 'Unit', 'Quantity', 'Price', 'Image', 'Location',
            // Product/clothing terms
            'Classic', 'Blue', 'Cotton', 'Shirt', 'Navy', 'Medium', 'Large', 'Small',
            'Indigo', 'Denim', 'Jeans', 'Premium', 'Black', 'White', 'Red', 'Green',
            'Gold', 'Silver', 'Style', 'Clothing', 'Shirts', 'Button', 'Down',
            'Straight', 'Fit', 'Thread', 'Fabric', 'Material', 'Design',
            // Common status words
            'Shipped', 'Delivered', 'Pending', 'Approved', 'Completed', 'Processing',
            'Canceled', 'Returned', 'Transit', 'Ground', 'Express', 'Standard',
            // Geographic (keep major cities but allow)
            'Distribution', 'Center', 'East', 'West', 'North', 'South', 'Warehouse',
            'Facility', 'Package', 'Carrier', 'Service', 'Ground', 'Air',
            // Measurements
            'Inches', 'Pounds', 'Ounces', 'Grams', 'Kilograms', 'Length', 'Width', 'Height',
            // Common e-commerce
            'Gift', 'Message', 'Notes', 'Tags', 'Summer', 'Winter', 'Collection', 'Sale',
            'Campaign', 'Website', 'Mobile', 'App', 'Chat', 'Support', 'Help',
            // Technology
            'Production', 'Development', 'Staging', 'Environment', 'Version', 'Request'
        ];
        
        return commonWords.includes(word);
    }

    /**
     * Display analysis results in the UI
     * @param {string} text - Original text
     * @param {number} totalCount - Total PII items found
     */
    displayResults(text, totalCount) {
        console.log('Displaying results...');
        
        const detectionResults = document.getElementById('detectionResults');
        const encryptionOptions = document.getElementById('encryptionOptions');
        
        if (totalCount === 0) {
            if (detectionResults) detectionResults.style.display = 'none';
            if (encryptionOptions) encryptionOptions.style.display = 'none';
            this.showToast('No PII detected in the text', 'success');
            return;
        }

        // Show sections
        if (detectionResults) detectionResults.style.display = 'block';
        if (encryptionOptions) encryptionOptions.style.display = 'block';

        this.displayHighlightedText(text);
        this.displayLegend();
        this.displayCounts(totalCount);
        
        console.log('Results displayed successfully');
    }

    /**
     * Display text with PII highlighted
     * @param {string} text - Text to highlight
     */
    /**
     * Display text with PII highlighted
     * @param {string} text - Text to highlight
     */
    displayHighlightedText(text) {
        const highlightedTextEl = document.getElementById('highlightedText');
        if (!highlightedTextEl) return;
        
        const allMatches = [];
        
        // Collect all matches
        Object.entries(this.detectedPII).forEach(([type, data]) => {
            data.matches.forEach(match => {
                allMatches.push({
                    ...match,
                    type,
                    color: data.color,
                    name: data.name
                });
            });
        });

        // For very large texts with many matches, use truncated display
        if (text.length > 500000 || allMatches.length > 1000) {
            this.displayTruncatedHighlightedText(text, allMatches);
            return;
        }

        // Standard highlighting for reasonable-sized content
        this.displayFullHighlightedText(text, allMatches, highlightedTextEl);
    }

    /**
     * Display full highlighted text for smaller content
     * @param {string} text - Original text
     * @param {Array} allMatches - All PII matches
     * @param {HTMLElement} container - Container element
     */
    displayFullHighlightedText(text, allMatches, container) {
        let highlightedText = text;

        // Sort by index and apply highlighting in reverse order
        allMatches.sort((a, b) => b.index - a.index);

        allMatches.forEach(match => {
            const start = match.index;
            const end = start + match.text.length;
            const highlighted = `<span class="pii-highlight" style="background-color: ${match.color}20; color: ${match.color}; border: 1px solid ${match.color}40;" title="${match.name}">${match.text}</span>`;
            
            highlightedText = highlightedText.slice(0, start) + highlighted + highlightedText.slice(end);
        });

        container.innerHTML = highlightedText;
    }

    /**
     * Display truncated view for very large content
     * @param {string} text - Original text
     * @param {Array} allMatches - All PII matches
     */
    displayTruncatedHighlightedText(text, allMatches) {
        const highlightedTextEl = document.getElementById('highlightedText');
        if (!highlightedTextEl) return;

        const previewLength = 50000; // Show first 50K characters
        const preview = text.substring(0, previewLength);
        const remainingLength = text.length - previewLength;
        
        // Filter matches that are within the preview
        const previewMatches = allMatches.filter(match => match.index < previewLength);
        
        let highlightedPreview = preview;
        
        // Sort by index and apply highlighting in reverse order
        previewMatches.sort((a, b) => b.index - a.index);

        previewMatches.forEach(match => {
            const start = match.index;
            const end = Math.min(start + match.text.length, previewLength);
            const highlighted = `<span class="pii-highlight" style="background-color: ${match.color}20; color: ${match.color}; border: 1px solid ${match.color}40;" title="${match.name}">${match.text.substring(0, end - start)}</span>`;
            
            highlightedPreview = highlightedPreview.slice(0, start) + highlighted + highlightedPreview.slice(end);
        });

        highlightedTextEl.innerHTML = `
            <div class="large-text-notice">
                <p><strong>📄 Large text detected:</strong> Showing first ${previewLength.toLocaleString()} characters of ${text.length.toLocaleString()} total.</p>
                <p>Found ${previewMatches.length} PII items in preview (${allMatches.length} total). Use processing options below to handle the full text.</p>
            </div>
            <div class="text-preview">${highlightedPreview}</div>
            ${remainingLength > 0 ? `<div class="truncation-notice">... and ${remainingLength.toLocaleString()} more characters</div>` : ''}
        `;
    }

    /**
     * Display legend for PII types
     */
    displayLegend() {
        const legendEl = document.getElementById('piiLegend');
        if (!legendEl) return;
        
        legendEl.innerHTML = '';

        Object.entries(this.detectedPII).forEach(([type, data]) => {
            const legendItem = document.createElement('div');
            legendItem.className = 'legend-item';
            legendItem.innerHTML = `
                <div class="legend-color" style="background-color: ${data.color}"></div>
                <span class="legend-text">${data.name}</span>
            `;
            legendEl.appendChild(legendItem);
        });
    }

    /**
     * Display PII count statistics
     * @param {number} totalCount - Total PII items found
     */
    displayCounts(totalCount) {
        const countsEl = document.getElementById('piiCounts');
        if (!countsEl) return;
        
        countsEl.innerHTML = `
            <div class="count-item">
                <div class="count-number">${totalCount}</div>
                <div class="count-label">Total PII Items</div>
            </div>
        `;

        Object.entries(this.detectedPII).forEach(([type, data]) => {
            const countItem = document.createElement('div');
            countItem.className = 'count-item';
            countItem.innerHTML = `
                <div class="count-number" style="color: ${data.color}">${data.count}</div>
                <div class="count-label">${data.name}</div>
            `;
            countsEl.appendChild(countItem);
        });
    }

    /**
     * Handle encryption method selection changes
     */
    handleEncryptionMethodChange() {
        const method = document.getElementById('encryptionMethod')?.value;
        const passwordGroup = document.getElementById('passwordGroup');
        
        if (passwordGroup) {
            passwordGroup.style.display = method === 'encrypt' ? 'block' : 'none';
        }
        
        // Show security warning for encryption
        if (method === 'encrypt') {
            this.showToast('⚠️ Demo encryption only! Not suitable for production use.', 'warning');
        }
    }

    /**
     * Process text with selected encryption method
     */
    async processText() {
        console.log('Starting text processing...');
        
        const inputText = document.getElementById('inputText')?.value?.trim();
        const method = document.getElementById('encryptionMethod')?.value || 'mask';
        const password = document.getElementById('encryptionPassword')?.value || '';

        if (!inputText) {
            this.showToast('❌ No text to process. Please analyze text first.', 'error');
            return;
        }

        if (Object.keys(this.detectedPII).length === 0) {
            this.showToast('❌ No PII detected. Please analyze text first to find PII to process.', 'error');
            return;
        }

        if (method === 'encrypt' && !password) {
            this.showToast('🔐 Password required for encryption. Please enter a secure password.', 'error');
            return;
        }

        if (method === 'encrypt' && password.length < 8) {
            this.showToast('🔐 Password must be at least 8 characters long for security.', 'error');
            return;
        }

        const enabledCount = Array.from(this.enabledTypes).reduce((count, type) => {
            return count + (this.detectedPII[type]?.count || 0);
        }, 0);

        if (enabledCount === 0) {
            this.showToast('⚠️ No PII types selected for processing. Please enable at least one PII type.', 'warning');
            return;
        }

        this.showLoading();

        try {
            const processedText = await this.applyEncryption(inputText, method, password);
            this.displayOutput(processedText);
            this.hideLoading();
            this.showToast(`✅ Successfully processed ${this.processedData.processedCount} PII items using ${this.processedData.method} method.`, 'success');
        } catch (error) {
            console.error('Processing error:', error);
            this.hideLoading();
            if (error.name === 'NotSupportedError') {
                this.showToast('❌ Encryption not supported in this browser. Try a different method.', 'error');
            } else {
                this.showToast('❌ Error processing text. Please check your input and try again.', 'error');
            }
        }
    }

    /**
     * Apply encryption/masking to detected PII
     * @param {string} text - Original text
     * @param {string} method - Processing method
     * @param {string} password - Encryption password (if needed)
     * @returns {Promise<string>} Processed text
     */
    async applyEncryption(text, method, password) {
        let processedText = text;
        let processedCount = 0;
        const originalCount = Object.values(this.detectedPII).reduce((sum, data) => sum + data.count, 0);

        // Collect enabled matches and sort by index (descending)
        const allMatches = [];
        Object.entries(this.detectedPII).forEach(([type, data]) => {
            if (this.enabledTypes.has(type)) {
                data.matches.forEach(match => allMatches.push(match));
            }
        });

        allMatches.sort((a, b) => b.index - a.index);

        // Apply encryption/masking
        for (const match of allMatches) {
            const start = match.index;
            const end = start + match.text.length;
            let replacement;

            switch (method) {
                case 'mask':
                    replacement = '*'.repeat(match.text.length);
                    break;
                case 'hash':
                    replacement = `[HASH:${await this.secureHash(match.text)}]`;
                    break;
                case 'encrypt':
                    replacement = await this.secureEncrypt(match.text, password);
                    break;
                case 'redact':
                    replacement = '[REDACTED]';
                    break;
                default:
                    replacement = match.text;
            }

            processedText = processedText.slice(0, start) + replacement + processedText.slice(end);
            processedCount++;
        }

        this.processedData = {
            originalCount,
            processedCount,
            method,
            securityLevel: this.getSecurityLevel(method)
        };

        return processedText;
    }

    /**
     * Generate a secure hash using Web Crypto API
     * @param {string} text - Text to hash
     * @returns {Promise<string>} SHA-256 hash in hex format
     */
    async secureHash(text) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(text);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 16);
        } catch (error) {
            console.warn('Secure hashing failed, falling back to simple hash:', error);
            return this.fallbackHash(text);
        }
    }

    /**
     * Fallback hash function for environments without Web Crypto API
     * @param {string} text - Text to hash
     * @returns {string} Simple hash
     */
    fallbackHash(text) {
        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32bit integer
        }
        return Math.abs(hash).toString(16).substring(0, 8);
    }

    /**
     * Generate encryption key from password using PBKDF2
     * @param {string} password - User password
     * @param {Uint8Array} salt - Cryptographic salt
     * @returns {Promise<CryptoKey>} Derived encryption key
     */
    async generateKey(password, salt) {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        return crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt text using AES-GCM with Web Crypto API
     * @param {string} text - Text to encrypt
     * @param {string} password - Encryption password
     * @returns {Promise<string>} Encrypted text with metadata
     */
    async secureEncrypt(text, password) {
        try {
            const encoder = new TextEncoder();
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const key = await this.generateKey(password, salt);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                encoder.encode(text)
            );
            
            // Combine salt, iv, and encrypted data
            const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(new Uint8Array(encrypted), salt.length + iv.length);
            
            return `[ENC:${btoa(String.fromCharCode(...combined)).substring(0, 24)}...]`;
        } catch (error) {
            console.warn('Secure encryption failed, using demo mode:', error);
            return this.demoEncrypt(text, password);
        }
    }

    /**
     * Demo encryption for fallback (XOR - NOT SECURE)
     * @param {string} text - Text to encrypt
     * @param {string} password - Password
     * @returns {string} Demo encrypted text
     */
    demoEncrypt(text, password) {
        // XOR encryption for demo purposes ONLY - NOT SECURE
        let result = '';
        for (let i = 0; i < text.length; i++) {
            result += String.fromCharCode(text.charCodeAt(i) ^ password.charCodeAt(i % password.length));
        }
        return `[DEMO:${btoa(result).substring(0, 12)}...]`;
    }

    /**
     * Get security level for encryption method
     * @param {string} method - Encryption method
     * @returns {string} Security level description
     */
    getSecurityLevel(method) {
        /** @type {Object.<string, string>} */
        const levels = {
            'encrypt': 'High (Demo Only)',
            'hash': 'High', 
            'redact': 'Medium',
            'mask': 'Low'
        };
        return levels[method] || 'None';
    }

    /**
     * Display processed text output and statistics
     * @param {string} processedText - The processed text
     */
    displayOutput(processedText) {
        const outputSection = document.getElementById('outputSection');
        const processedTextEl = document.getElementById('processedText');
        const outputStatsEl = document.getElementById('outputStats');

        if (outputSection) outputSection.style.display = 'block';
        if (processedTextEl) processedTextEl.textContent = processedText;
        
        this.processedText = processedText;

        if (outputStatsEl && this.processedData) {
            const { originalCount, processedCount, method, securityLevel } = this.processedData;
            
            outputStatsEl.innerHTML = `
                <div class="stat-item">
                    <div class="stat-value">${originalCount}</div>
                    <div class="stat-label">Original PII Count</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${processedCount}</div>
                    <div class="stat-label">Processed PII Count</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${securityLevel}</div>
                    <div class="stat-label">Security Level</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${method.charAt(0).toUpperCase() + method.slice(1)}</div>
                    <div class="stat-label">Method Used</div>
                </div>
            `;
        }
    }

    /**
     * Copy processed text to clipboard
     */
    copyToClipboard() {
        if (!this.processedText) {
            this.showToast('❌ No processed text to copy. Please process text first.', 'error');
            return;
        }

        navigator.clipboard.writeText(this.processedText).then(() => {
            this.showToast('📋 Successfully copied to clipboard!', 'success');
        }).catch((error) => {
            console.error('Clipboard error:', error);
            this.showToast('❌ Failed to copy to clipboard. Please copy manually.', 'error');
        });
    }

    /**
     * Download processed text as file
     */
    downloadText() {
        if (!this.processedText) {
            this.showToast('❌ No processed text to download. Please process text first.', 'error');
            return;
        }

        const blob = new Blob([this.processedText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `processed-text-${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        this.showToast('💾 File downloaded successfully!', 'success');
    }

    /**
     * Clear all data and reset the application state
     */
    clearAll() {
        console.log('Clearing all data...');
        
        const inputText = document.getElementById('inputText');
        const encryptionPassword = document.getElementById('encryptionPassword');
        
        if (inputText) inputText.value = '';
        if (encryptionPassword) encryptionPassword.value = '';
        
        // Hide sections
        ['detectionResults', 'encryptionOptions', 'outputSection'].forEach(id => {
            const element = document.getElementById(id);
            if (element) element.style.display = 'none';
        });
        
        // Reset data
        this.detectedPII = {};
        this.processedText = '';
        this.processedData = {};
        this.enabledTypes = new Set(Object.keys(this.piiPatterns));
        
        // Reset toggles
        document.querySelectorAll('.toggle-switch').forEach(toggle => {
            toggle.classList.add('active');
        });
        
        this.hideLoading();
        this.showToast('🧹 All data cleared successfully!', 'success');
    }

    /**
     * Show loading overlay
     */
    showLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.add('show');
            console.log('Loading overlay shown');
        }
    }

    /**
     * Hide loading overlay
     */
    hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.classList.remove('show');
            // Remove any progress indicators
            const progressEl = overlay.querySelector('.progress-info');
            if (progressEl) {
                progressEl.remove();
            }
            console.log('Loading overlay hidden');
        } else {
            console.warn('Loading overlay element not found');
        }
    }

    /**
     * Show toast notification to user
     * @param {string} message - Message to display
     * @param {string} type - Toast type (success, error, warning)
     */
    showToast(message, type = 'success') {
        const toast = document.getElementById('toast');
        if (!toast) return;
        
        toast.textContent = message;
        toast.className = `toast ${type} show`;
        toast.setAttribute('aria-live', 'polite');
        toast.setAttribute('role', 'status');
        
        const duration = type === 'warning' ? 5000 : 3000;
        setTimeout(() => {
            toast.className = toast.className.replace('show', 'hidden');
        }, duration);
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing PII Tool...');
    window.piiTool = new PIITool();
});