# Ultimate Email Scraper - Final Version

A robust, high-success-rate email scraper designed to maximize extraction from websites while being respectful and reliable.

## 🚀 Key Features

- **High Success Rate**: Advanced error handling and retry logic
- **Smart Crawling**: Prioritizes contact/about pages, respects robots.txt
- **Multiple Email Detection**: Regex, mailto links, JSON-LD, obfuscated emails
- **Robust Error Handling**: Handles timeouts, connection errors, and blocked content
- **Rate Limiting**: Configurable delays and concurrency limits
- **User Agent Rotation**: Realistic browser headers
- **Comprehensive Logging**: Detailed progress and statistics
- **Easy to Use**: Simple command-line interface

## 📦 Installation

1. **Install Python 3.8+** (if not already installed)

2. **Install dependencies**:
   ```bash
   pip install -r requirements_final.txt
   ```

   Or use the auto-installer:
   ```bash
   python run_scraper_final.py
   ```

## 🎯 Quick Start

### Basic Usage
```bash
python email_scraper_final.py --input websites_test.csv
```

### Advanced Usage
```bash
python email_scraper_final.py \
  --input websites_test.csv \
  --output my_emails.csv \
  --concurrent 8 \
  --per-domain 3 \
  --delay-min 1.5 \
  --delay-max 3.0 \
  --timeout 25 \
  --retries 2
```

## 📋 Input Format

Create a CSV or text file with one URL per line:

**websites_test.csv**:
```csv
https://example.com
https://another-site.com
example.org
```

**Or text file**:
```
https://example.com
https://another-site.com
example.org
```

## ⚙️ Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `--input`, `-i` | Input file with URLs | Required |
| `--output`, `-o` | Output CSV file | `emails_found.csv` |
| `--concurrent`, `-c` | Max concurrent requests | `10` |
| `--per-domain`, `-d` | Max requests per domain | `5` |
| `--delay-min` | Minimum delay between requests | `1.0` |
| `--delay-max` | Maximum delay between requests | `3.0` |
| `--timeout`, `-t` | Request timeout in seconds | `30` |
| `--retries`, `-r` | Max retries per request | `3` |
| `--no-robots` | Ignore robots.txt | `False` |

## 📊 Output Format

The scraper generates a CSV file with the following columns:

| Column | Description |
|--------|-------------|
| `domain` | Website domain |
| `email` | Found email address |
| `source_url` | URL where email was found |
| `found_at` | Timestamp of discovery |
| `http_status` | HTTP response status |
| `user_agent` | User agent used for request |

## 🔧 How It Works

1. **URL Loading**: Reads URLs from input file
2. **Priority Processing**: Processes main pages first, then contact/about pages
3. **Smart Crawling**: Follows links within the same domain
4. **Email Extraction**: Uses multiple methods to find emails:
   - Direct regex matching
   - BeautifulSoup parsing
   - Mailto link extraction
   - JSON-LD structured data
   - Obfuscated email detection
5. **Error Handling**: Retries failed requests with exponential backoff
6. **Rate Limiting**: Respects delays and concurrency limits
7. **Results Saving**: Outputs findings to CSV file

## 🛡️ Built-in Protections

- **Respectful Crawling**: Configurable delays and rate limiting
- **Robots.txt Compliance**: Respects website crawling policies
- **Error Recovery**: Handles network issues and timeouts gracefully
- **Domain Limits**: Prevents over-crawling individual domains
- **Content Filtering**: Skips non-HTML content and irrelevant pages

## 📈 Success Rate Optimization

This scraper is designed for maximum success by:

1. **Multiple Detection Methods**: Uses various techniques to find emails
2. **Robust Error Handling**: Retries failed requests intelligently
3. **Smart URL Prioritization**: Focuses on pages likely to contain contact info
4. **Realistic Headers**: Uses rotating user agents and proper headers
5. **Flexible Timeouts**: Handles slow-responding websites
6. **Content Type Detection**: Only processes HTML content

## 🚨 Troubleshooting

### Common Issues

1. **"No URLs found"**: Check your input file format
2. **"Connection errors"**: Some sites may be down or blocking requests
3. **"Low success rate"**: Try increasing delays or reducing concurrency
4. **"Timeout errors"**: Increase the timeout value

### Tips for Better Results

1. **Use realistic delays**: 1.5-3 seconds between requests
2. **Limit concurrency**: 8-10 concurrent requests max
3. **Check input URLs**: Ensure URLs are valid and accessible
4. **Monitor output**: Check the console for progress and errors

## 📝 Example Output

```
🚀 Starting Ultimate Email Scraper
📁 Input file: websites_test.csv
📁 Output file: emails_found.csv
⚙️  Max concurrent: 8
⚙️  Max per domain: 3
⏱️  Delay: 1.5-3.0s
⏰ Timeout: 25s
--------------------------------------------------
📋 Loaded 15 URLs to process
  ✅ melanie.co | https://melanie.co/ | Status: 200
    📧 Found 2 emails
  ✅ k.me | https://k.me/ | Status: 200
    📧 Found 1 emails
  ❌ sen.film | https://sen.film/ | Status: 0
  ✅ makarov.video | https://makarov.video/ | Status: 200
    📧 Found 3 emails

📊 Results saved to: emails_found.csv
📧 Total emails found: 12

📈 Final Statistics:
  ⏱️  Time elapsed: 45.2 seconds
  🔗 URLs processed: 15
  ✅ Successful: 12
  ❌ Failed: 3
  📧 Emails found: 12
  📊 Success rate: 80.0%
```

## 🔄 Updates and Improvements

This final version includes:

- ✅ Simplified architecture for better reliability
- ✅ Enhanced error handling and retry logic
- ✅ Multiple email detection methods
- ✅ Smart URL prioritization
- ✅ Realistic user agent rotation
- ✅ Comprehensive logging and statistics
- ✅ Easy-to-use command-line interface
- ✅ Robust timeout and connection handling

## 📞 Support

If you encounter issues:

1. Check the console output for error messages
2. Verify your input file format
3. Try adjusting timeout and delay settings
4. Ensure you have a stable internet connection

The scraper is designed to be robust and handle most common issues automatically.