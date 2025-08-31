# 🔒 PII Detection & Encryption Tool

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![JavaScript](https://img.shields.io/badge/JavaScript-ES6+-yellow.svg)
![CSS](https://img.shields.io/badge/CSS-3-blue.svg)
![HTML](https://img.shields.io/badge/HTML-5-orange.svg)

A comprehensive web application for detecting and securing Personally Identifiable Information (PII) in text documents. Built with vanilla JavaScript and modern web standards, this tool provides enterprise-grade PII detection capabilities with multiple security processing options.

## 🚀 **Live Demo**

Simply open `index.html` in any modern web browser to start using the tool immediately.

## ✨ **Key Features**

### 🔍 **Advanced PII Detection**
- **25+ PII Pattern Types**: Email, phone, SSN, credit cards, addresses, names, and more
- **Production-Grade Patterns**: Luhn algorithm for credit card validation, SSN prefix validation
- **Context-Aware Detection**: Smart filtering to avoid false positives in business contexts
- **JSON Structure Protection**: Preserves data structure while detecting PII values
- **Real-Time Analysis**: Instant highlighting and categorization of detected PII

### 🛡️ **Multiple Security Processing Methods**
- **🎭 Masking**: Replace PII with asterisks (`john@email.com` → `*************`)
- **🔗 Hashing**: SHA-256 secure hashing with salt
- **🔐 Encryption**: AES-GCM encryption with PBKDF2 key derivation
- **📝 Redaction**: Complete removal with `[REDACTED]` placeholder

### 🎨 **Enterprise-Ready UI/UX**
- **Responsive Design**: Mobile-first, accessible on all devices
- **Dark/Light Mode**: Automatic theme switching
- **Accessibility First**: WCAG 2.1 AA compliant with screen reader support
- **Intuitive Controls**: Drag-and-drop text input, one-click processing
- **Visual Feedback**: Color-coded PII highlighting and progress indicators

### ⚡ **Performance Optimized**
- **Large Text Handling**: Processes documents up to 1M+ characters
- **Chunked Processing**: Async processing with progress indicators
- **Memory Efficient**: Smart rendering for large datasets
- **No Dependencies**: Pure vanilla JavaScript - no external libraries

## 📋 **Supported PII Types**

| Category | Types | Examples |
|----------|-------|----------|
| **Contact Info** | Email, Phone, Address, ZIP | `user@email.com`, `(555) 123-4567` |
| **Identity** | SSN, Passport, Driver's License, Tax ID | `123-45-6789`, `USA123456789` |
| **Financial** | Credit Cards, Bank Accounts, Routing Numbers | `4111-1111-1111-1111`, `123456789` |
| **Personal** | Names, Dates of Birth, Ages | `John Smith`, `March 15, 1985` |
| **Digital** | IP Addresses, MAC Addresses, URLs | `192.168.1.1`, `https://example.com` |
| **Business** | Order IDs, Tracking Numbers, Customer IDs | `ORD-2024-123`, `1Z999AA1234567890` |
| **Medical** | Medical License, DEA Numbers, NPI | `CA-MD-123456`, `BW1234567` |
| **Geographic** | Addresses, Apartments, PO Boxes | `123 Main St`, `Apt 4B`, `PO Box 123` |

## 🏗️ **Architecture**

```
├── index.html          # Main application interface
├── app.js             # Core PII detection and encryption logic
├── style.css          # Modern CSS with design system
├── demo-pii-data.json # Sample test data (15K characters)
├── script.py          # Pattern development utilities
└── README.md          # Documentation
```

### **Core Components**

#### **PIITool Class (`app.js`)**
- **Pattern Engine**: 25+ regex patterns with priority-based matching
- **Crypto Module**: Web Crypto API integration for secure operations
- **UI Controller**: DOM manipulation and event handling
- **Performance Manager**: Chunked processing for large documents

#### **Design System (`style.css`)**
- **CSS Custom Properties**: Consistent theming and spacing
- **Component Architecture**: Modular, reusable UI components
- **Responsive Grid**: Mobile-first layout system
- **Accessibility**: High contrast, focus indicators, screen reader support

## 🚦 **Getting Started**

### **Quick Start**
1. **Download** or clone this repository
2. **Open** `index.html` in any modern web browser
3. **Paste** or type text into the input area
4. **Click** "Analyze Text" to detect PII
5. **Select** processing method and click "Process PII"

### **Sample Data**
The tool includes comprehensive test data in `demo-pii-data.json` with:
- Employee records with personal information
- Customer service interactions
- Medical records with HIPAA-regulated data
- Financial transactions
- Government and educational records

### **Browser Requirements**
- **Modern Browsers**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **JavaScript**: ES6+ support required
- **Web Crypto API**: For secure encryption features
- **Local Storage**: For settings persistence

## 🔧 **Configuration**

### **PII Pattern Customization**
Add new PII patterns by extending the `piiPatterns` object in `app.js`:

```javascript
this.piiPatterns = {
    customPattern: {
        pattern: /your-regex-here/g,
        name: "Custom PII Type",
        color: "#FF6B6B",
        priority: 1,
        contextAware: true // Optional: enables smart filtering
    }
}
```

### **Processing Methods**
- **Masking**: Simple asterisk replacement
- **Hashing**: SHA-256 with random salt
- **Encryption**: AES-GCM with PBKDF2 (demo implementation)
- **Redaction**: Complete text removal

### **Security Levels**
| Method | Security Level | Use Case |
|--------|---------------|----------|
| **Encryption** | High* | Reversible protection |
| **Hashing** | High | Irreversible anonymization |
| **Redaction** | Medium | Document sanitization |
| **Masking** | Low | Visual privacy |

*Demo implementation only - use server-side encryption for production

## 🎯 **Use Cases**

### **Enterprise Data Protection**
- **HR Documents**: Employee records, resumes, performance reviews
- **Customer Data**: Support tickets, feedback forms, user profiles
- **Financial Records**: Transaction logs, payment information, tax documents
- **Healthcare**: Patient records, insurance forms, medical reports

### **Development & Testing**
- **Database Sanitization**: Clean test data for development environments
- **API Testing**: Generate realistic but safe test datasets
- **Compliance Auditing**: Identify PII in code, logs, and documentation
- **Data Migration**: Secure PII during system transitions

### **Legal & Compliance**
- **GDPR Compliance**: Right to be forgotten implementations
- **HIPAA Protection**: Medical record anonymization
- **PCI DSS**: Credit card data protection
- **SOX Compliance**: Financial document security

## 🔒 **Security Considerations**

### **⚠️ Important Security Notice**
This tool is designed for **demonstration and development purposes**. For production use:

- **Server-Side Processing**: Implement PII detection on secure servers
- **Production Encryption**: Use enterprise-grade encryption libraries
- **Key Management**: Implement proper cryptographic key storage
- **Audit Logging**: Track all PII access and processing
- **Network Security**: Use HTTPS and secure data transmission

### **Best Practices**
1. **Never** process real sensitive data in client-side applications
2. **Always** validate and sanitize user inputs
3. **Use** secure, audited encryption libraries for production
4. **Implement** proper access controls and authentication
5. **Regular** security audits and penetration testing

## 📊 **Performance**

### **Benchmarks**
- **Small Text** (<1K chars): ~10ms processing time
- **Medium Text** (1K-50K chars): ~100ms processing time
- **Large Text** (50K-500K chars): ~1-5s with progress indicators
- **Very Large Text** (500K+ chars): Chunked processing with UI feedback

### **Memory Usage**
- **Base Application**: ~2-5MB
- **Large Document Processing**: ~10-50MB depending on content
- **Pattern Matching**: O(n) time complexity per pattern

## 🤝 **Contributing**

### **Development Setup**
1. Clone the repository
2. Open in your preferred IDE
3. Make changes to HTML, CSS, or JavaScript
4. Test in multiple browsers
5. Submit pull requests

### **Adding New PII Patterns**
1. **Define Pattern**: Add regex to `piiPatterns` object
2. **Set Priority**: Lower numbers = higher precedence
3. **Add Color**: Unique color for visual distinction
4. **Test Thoroughly**: Validate against false positives
5. **Update Documentation**: Add to supported types list

### **Code Style**
- **JavaScript**: ES6+ features, JSDoc documentation
- **CSS**: BEM methodology, custom properties
- **HTML**: Semantic markup, accessibility attributes
- **Comments**: Clear explanations for complex logic

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- **Microsoft Presidio**: Inspiration for enterprise PII detection patterns
- **Web Crypto API**: Secure client-side cryptographic operations
- **OWASP**: Security best practices and guidelines
- **WCAG**: Accessibility standards and compliance

## 📞 **Support**

For questions, issues, or feature requests:
- **GitHub Issues**: Report bugs and request features
- **Documentation**: Comprehensive inline code comments
- **Community**: Contribute to the open-source ecosystem

---

**⚠️ Disclaimer**: This tool is for educational and development purposes. Always implement proper server-side security measures for production use with real sensitive data.

**🔐 Security First**: Protect user privacy and comply with applicable data protection regulations in your jurisdiction.

---

*Made with ❤️ for the privacy and security community*
