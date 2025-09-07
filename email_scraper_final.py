#!/usr/bin/env python3
"""
Ultimate Email Scraper - Final Version
Maximizes success rate with robust error handling and multiple fallback strategies
"""

import asyncio
import csv
import json
import random
import re
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag

import aiohttp
from bs4 import BeautifulSoup
import tldextract


# Configuration
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
]

# Email patterns
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
OBFUSCATED_EMAIL_REGEX = re.compile(
    r'([a-zA-Z0-9._%+-]+)\s*(?:\[at\]|\(at\)|\sat\s|\sat\b|@)\s*([a-zA-Z0-9.-]+)\s*(?:\[dot\]|\(dot\)|\sdot\s|\.|\bdot\b)\s*([a-zA-Z]{2,})',
    re.IGNORECASE
)

# Phone patterns
PHONE_REGEX = re.compile(r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}')

# Social media domains
SOCIAL_DOMAINS = {
    'linkedin.com', 'facebook.com', 'fb.com', 'instagram.com', 
    'twitter.com', 'x.com', 'tiktok.com', 'youtube.com', 'youtu.be'
}

# File extensions to skip
SKIP_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.jpg', '.jpeg', '.png',
    '.gif', '.svg', '.webp', '.mp3', '.mp4', '.avi', '.mov',
    '.css', '.js', '.ico', '.xml', '.json'
}


@dataclass
class ScrapeResult:
    domain: str
    email: str
    source_url: str
    found_at: str
    http_status: int = 200
    user_agent: str = ""


class RobustEmailScraper:
    def __init__(
        self,
        input_file: str,
        output_file: str = "emails_found.csv",
        max_concurrent: int = 10,
        max_per_domain: int = 5,
        delay_min: float = 1.0,
        delay_max: float = 3.0,
        timeout: int = 30,
        use_proxies: bool = False,
        max_retries: int = 3,
        respect_robots: bool = True
    ):
        self.input_file = input_file
        self.output_file = output_file
        self.max_concurrent = max_concurrent
        self.max_per_domain = max_per_domain
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.timeout = timeout
        self.use_proxies = use_proxies
        self.max_retries = max_retries
        self.respect_robots = respect_robots
        
        # Internal state
        self.visited_urls: Set[str] = set()
        self.domain_counts: Dict[str, int] = defaultdict(int)
        self.results: List[ScrapeResult] = []
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.domain_semaphores: Dict[str, asyncio.Semaphore] = defaultdict(lambda: asyncio.Semaphore(max_per_domain))
        
        # Statistics
        self.stats = {
            'total_processed': 0,
            'successful': 0,
            'failed': 0,
            'emails_found': 0,
            'start_time': time.time()
        }

    def normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and ensuring proper format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        url, _ = urldefrag(url)
        return url

    def get_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            return domain
        except:
            return ""

    def should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped based on extension or other criteria"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Skip file extensions
        for ext in SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        
        # Skip common non-content paths
        skip_patterns = [
            '/admin', '/login', '/register', '/api/', '/ajax/',
            '/static/', '/assets/', '/css/', '/js/', '/images/',
            '/img/', '/fonts/', '/media/', '/uploads/'
        ]
        
        for pattern in skip_patterns:
            if pattern in path:
                return True
        
        return False

    def is_priority_url(self, url: str) -> bool:
        """Check if URL is high priority (contact, about, etc.)"""
        path = urlparse(url).path.lower()
        priority_keywords = ['contact', 'about', 'support', 'help', 'team', 'staff']
        return any(keyword in path for keyword in priority_keywords)

    async def get_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(DEFAULT_USER_AGENTS)

    async def create_session(self) -> aiohttp.ClientSession:
        """Create HTTP session with proper configuration"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False,  # More permissive SSL
            enable_cleanup_closed=True
        )
        
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        }
        
        return aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            trust_env=True,
            auto_decompress=True  # Enable automatic decompression
        )

    async def fetch_url(self, url: str, retry_count: int = 0) -> Tuple[bool, str, int, str]:
        """Fetch URL with retry logic and error handling"""
        if retry_count >= self.max_retries:
            return False, "", 0, ""
        
        try:
            user_agent = await self.get_user_agent()
            headers = {
                'User-Agent': user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            async with self.session.get(url, headers=headers, allow_redirects=True) as response:
                # Handle different response types
                if response.status == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    if 'text/html' in content_type or 'application/xhtml' in content_type or 'text/plain' in content_type:
                        try:
                            text = await response.text(errors='ignore')
                            return True, text, response.status, user_agent
                        except Exception as e:
                            print(f"  ⚠️  Text decode error for {url}: {e}")
                            return False, "", response.status, user_agent
                    else:
                        return False, "", response.status, user_agent
                elif response.status in [301, 302, 303, 307, 308]:
                    # Follow redirects
                    redirect_url = response.headers.get('location')
                    if redirect_url:
                        redirect_url = urljoin(url, redirect_url)
                        return await self.fetch_url(redirect_url, retry_count)
                elif response.status == 403:
                    # Try with different headers for 403 errors
                    if retry_count == 0:
                        headers['Referer'] = 'https://www.google.com/'
                        return await self.fetch_url(url, retry_count + 1)
                    return False, "", response.status, user_agent
                else:
                    return False, "", response.status, user_agent
                    
        except asyncio.TimeoutError:
            if retry_count < self.max_retries - 1:
                await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                return await self.fetch_url(url, retry_count + 1)
            print(f"  ⏰ Timeout for {url}")
            return False, "", 408, ""
        except aiohttp.ClientError as e:
            if retry_count < self.max_retries - 1:
                await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                return await self.fetch_url(url, retry_count + 1)
            print(f"  ❌ Client error for {url}: {e}")
            return False, "", 0, ""
        except Exception as e:
            if retry_count < self.max_retries - 1:
                await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                return await self.fetch_url(url, retry_count + 1)
            print(f"  ❌ Unexpected error for {url}: {e}")
            return False, "", 0, ""

    def extract_emails(self, html: str, url: str) -> Set[str]:
        """Extract emails from HTML content using multiple methods"""
        emails = set()
        
        try:
            # Method 1: Direct regex on HTML
            for match in EMAIL_REGEX.finditer(html):
                email = match.group().lower().strip()
                if self.is_valid_email(email):
                    emails.add(email)
            
            # Method 2: BeautifulSoup parsing
            soup = BeautifulSoup(html, 'html.parser')
            
            # Extract from mailto links
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('mailto:'):
                    email = href[7:].split('?')[0].strip()
                    if self.is_valid_email(email):
                        emails.add(email.lower())
            
            # Extract from text content
            text_content = soup.get_text()
            for match in EMAIL_REGEX.finditer(text_content):
                email = match.group().lower().strip()
                if self.is_valid_email(email):
                    emails.add(email)
            
            # Method 3: Handle obfuscated emails
            for match in OBFUSCATED_EMAIL_REGEX.finditer(text_content):
                local, domain, tld = match.groups()
                email = f"{local}@{domain}.{tld}".lower()
                if self.is_valid_email(email):
                    emails.add(email)
            
            # Method 4: JSON-LD structured data
            for script in soup.find_all('script', type='application/ld+json'):
                try:
                    data = json.loads(script.string)
                    emails.update(self.extract_emails_from_json(data))
                except:
                    continue
            
        except Exception as e:
            print(f"  ⚠️  Email extraction error for {url}: {e}")
        
        return emails

    def extract_emails_from_json(self, data) -> Set[str]:
        """Recursively extract emails from JSON data"""
        emails = set()
        
        if isinstance(data, dict):
            for value in data.values():
                emails.update(self.extract_emails_from_json(value))
        elif isinstance(data, list):
            for item in data:
                emails.update(self.extract_emails_from_json(item))
        elif isinstance(data, str):
            for match in EMAIL_REGEX.finditer(data):
                email = match.group().lower().strip()
                if self.is_valid_email(email):
                    emails.add(email)
        
        return emails

    def is_valid_email(self, email: str) -> bool:
        """Validate email format"""
        if not email or len(email) > 254:
            return False
        
        # Basic format check
        if not EMAIL_REGEX.match(email):
            return False
        
        # Check for common invalid patterns
        invalid_patterns = [
            'example.com', 'test.com', 'sample.com', 'domain.com',
            'your-email', 'email@example', 'noreply@', 'no-reply@'
        ]
        
        for pattern in invalid_patterns:
            if pattern in email.lower():
                return False
        
        return True

    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract relevant links from HTML"""
        links = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            domain = self.get_domain(base_url)
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Convert relative URLs to absolute
                if href.startswith('/'):
                    href = urljoin(base_url, href)
                elif not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                # Normalize URL
                href = self.normalize_url(href)
                
                # Check if it's from the same domain
                if self.get_domain(href) == domain:
                    # Skip if it should be skipped
                    if not self.should_skip_url(href):
                        links.append(href)
        
        except Exception as e:
            print(f"  ⚠️  Link extraction error for {base_url}: {e}")
        
        return links

    async def process_url(self, url: str, priority: bool = False) -> None:
        """Process a single URL"""
        domain = self.get_domain(url)
        
        # Check domain limits
        if self.domain_counts[domain] >= self.max_per_domain:
            return
        
        # Skip if already visited
        if url in self.visited_urls:
            return
        
        # Skip if should be skipped
        if self.should_skip_url(url):
            return
        
        self.visited_urls.add(url)
        self.domain_counts[domain] += 1
        self.stats['total_processed'] += 1
        
        async with self.semaphore:
            async with self.domain_semaphores[domain]:
                # Add delay
                delay = random.uniform(self.delay_min, self.delay_max)
                await asyncio.sleep(delay)
                
                # Fetch URL
                success, html, status, user_agent = await self.fetch_url(url)
                
                if success and html:
                    self.stats['successful'] += 1
                    print(f"  ✅ {domain} | {url} | Status: {status}")
                    
                    # Extract emails
                    emails = self.extract_emails(html, url)
                    
                    if emails:
                        self.stats['emails_found'] += len(emails)
                        print(f"    📧 Found {len(emails)} emails")
                        
                        for email in emails:
                            result = ScrapeResult(
                                domain=domain,
                                email=email,
                                source_url=url,
                                found_at=datetime.now().isoformat(),
                                http_status=status,
                                user_agent=user_agent
                            )
                            self.results.append(result)
                    
                    # Extract links for further crawling (only for priority URLs or main pages)
                    if priority or self.is_priority_url(url):
                        links = self.extract_links(html, url)
                        # Limit links to prevent infinite crawling
                        for link in links[:10]:  # Only take first 10 links
                            if link not in self.visited_urls:
                                await self.process_url(link, priority=False)
                
                else:
                    self.stats['failed'] += 1
                    print(f"  ❌ {domain} | {url} | Status: {status}")

    async def load_urls(self) -> List[str]:
        """Load URLs from input file"""
        urls = []
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                if self.input_file.endswith('.csv'):
                    reader = csv.reader(f)
                    for row in reader:
                        if row and row[0].strip():
                            url = self.normalize_url(row[0].strip())
                            urls.append(url)
                else:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            url = self.normalize_url(line)
                            urls.append(url)
        except FileNotFoundError:
            print(f"❌ Input file not found: {self.input_file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading input file: {e}")
            sys.exit(1)
        
        return urls

    async def save_results(self) -> None:
        """Save results to CSV file"""
        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['domain', 'email', 'source_url', 'found_at', 'http_status', 'user_agent'])
                
                for result in self.results:
                    writer.writerow([
                        result.domain,
                        result.email,
                        result.source_url,
                        result.found_at,
                        result.http_status,
                        result.user_agent
                    ])
            
            print(f"\n📊 Results saved to: {self.output_file}")
            print(f"📧 Total emails found: {len(self.results)}")
            
        except Exception as e:
            print(f"❌ Error saving results: {e}")

    def print_stats(self) -> None:
        """Print final statistics"""
        elapsed = time.time() - self.stats['start_time']
        
        print(f"\n📈 Final Statistics:")
        print(f"  ⏱️  Time elapsed: {elapsed:.1f} seconds")
        print(f"  🔗 URLs processed: {self.stats['total_processed']}")
        print(f"  ✅ Successful: {self.stats['successful']}")
        print(f"  ❌ Failed: {self.stats['failed']}")
        print(f"  📧 Emails found: {self.stats['emails_found']}")
        
        if self.stats['total_processed'] > 0:
            success_rate = (self.stats['successful'] / self.stats['total_processed']) * 100
            print(f"  📊 Success rate: {success_rate:.1f}%")

    async def run(self) -> None:
        """Main execution method"""
        print("🚀 Starting Ultimate Email Scraper")
        print(f"📁 Input file: {self.input_file}")
        print(f"📁 Output file: {self.output_file}")
        print(f"⚙️  Max concurrent: {self.max_concurrent}")
        print(f"⚙️  Max per domain: {self.max_per_domain}")
        print(f"⏱️  Delay: {self.delay_min}-{self.delay_max}s")
        print(f"⏰ Timeout: {self.timeout}s")
        print("-" * 50)
        
        # Load URLs
        urls = await self.load_urls()
        if not urls:
            print("❌ No URLs found in input file")
            return
        
        print(f"📋 Loaded {len(urls)} URLs to process")
        
        # Create session
        self.session = await self.create_session()
        
        try:
            # Process URLs with priority for main pages
            tasks = []
            for i, url in enumerate(urls):
                priority = i < 5  # First 5 URLs are priority
                task = asyncio.create_task(self.process_url(url, priority))
                tasks.append(task)
            
            # Wait for all tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            # Close session
            if self.session:
                await self.session.close()
        
        # Save results and print stats
        await self.save_results()
        self.print_stats()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Ultimate Email Scraper - Final Version')
    parser.add_argument('--input', '-i', required=True, help='Input file with URLs (CSV or text)')
    parser.add_argument('--output', '-o', default='emails_found.csv', help='Output CSV file')
    parser.add_argument('--concurrent', '-c', type=int, default=10, help='Max concurrent requests')
    parser.add_argument('--per-domain', '-d', type=int, default=5, help='Max requests per domain')
    parser.add_argument('--delay-min', type=float, default=1.0, help='Minimum delay between requests')
    parser.add_argument('--delay-max', type=float, default=3.0, help='Maximum delay between requests')
    parser.add_argument('--timeout', '-t', type=int, default=30, help='Request timeout in seconds')
    parser.add_argument('--retries', '-r', type=int, default=3, help='Max retries per request')
    parser.add_argument('--no-robots', action='store_true', help='Ignore robots.txt')
    
    args = parser.parse_args()
    
    # Create scraper
    scraper = RobustEmailScraper(
        input_file=args.input,
        output_file=args.output,
        max_concurrent=args.concurrent,
        max_per_domain=args.per_domain,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        timeout=args.timeout,
        max_retries=args.retries,
        respect_robots=not args.no_robots
    )
    
    # Run scraper
    try:
        asyncio.run(scraper.run())
    except KeyboardInterrupt:
        print("\n⏹️  Scraping interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()