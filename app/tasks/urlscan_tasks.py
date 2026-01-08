"""URL Scan Tasks for Celery - Web page scanning with Playwright."""

import uuid
import os
import base64
import re
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

from app import celery
from app.services.elasticsearch_service import ElasticsearchService

import logging
logger = logging.getLogger('celery.tasks')


def _is_valid_url(url: str) -> bool:
    """Validate URL format."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False


def _extract_links_from_page(page) -> List[Dict]:
    """
    Extract all links from the page using Playwright.
    
    Returns list of dicts with href, text, and type.
    """
    links = []
    try:
        # Get all anchor elements
        anchors = page.query_selector_all('a[href]')
        for anchor in anchors:
            try:
                href = anchor.get_attribute('href')
                text = anchor.inner_text().strip() or anchor.get_attribute('title') or ''
                
                # Skip empty or javascript links
                if not href or href.startswith('javascript:') or href == '#':
                    continue
                
                # Determine link type
                link_type = 'internal'
                if href.startswith(('http://', 'https://')):
                    link_type = 'external'
                elif href.startswith('mailto:'):
                    link_type = 'email'
                elif href.startswith('tel:'):
                    link_type = 'phone'
                elif href.startswith('//'):
                    link_type = 'protocol-relative'
                
                links.append({
                    'href': href,
                    'text': text[:200] if text else '',  # Limit text length
                    'type': link_type
                })
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"Error extracting links: {e}")
    
    return links


def _extract_metadata(page) -> Dict:
    """Extract page metadata (title, description, etc.)."""
    metadata = {}
    try:
        # Title
        metadata['title'] = page.title() or ''
        
        # Meta description
        desc_el = page.query_selector('meta[name="description"]')
        if desc_el:
            metadata['description'] = desc_el.get_attribute('content') or ''
        
        # Meta keywords
        keywords_el = page.query_selector('meta[name="keywords"]')
        if keywords_el:
            metadata['keywords'] = keywords_el.get_attribute('content') or ''
        
        # Canonical URL
        canonical_el = page.query_selector('link[rel="canonical"]')
        if canonical_el:
            metadata['canonical'] = canonical_el.get_attribute('href') or ''
        
        # Open Graph data
        og_data = {}
        og_elements = page.query_selector_all('meta[property^="og:"]')
        for el in og_elements:
            prop = el.get_attribute('property')
            content = el.get_attribute('content')
            if prop and content:
                og_data[prop.replace('og:', '')] = content
        if og_data:
            metadata['open_graph'] = og_data
        
        # Favicon
        favicon_el = page.query_selector('link[rel="icon"], link[rel="shortcut icon"]')
        if favicon_el:
            metadata['favicon'] = favicon_el.get_attribute('href') or ''
        
    except Exception as e:
        logger.warning(f"Error extracting metadata: {e}")
    
    return metadata


def _extract_forms(page) -> List[Dict]:
    """Extract form information from the page."""
    forms = []
    try:
        form_elements = page.query_selector_all('form')
        for form in form_elements:
            try:
                form_data = {
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'id': form.get_attribute('id') or '',
                    'name': form.get_attribute('name') or ''
                }
                
                # Get input fields
                inputs = form.query_selector_all('input, select, textarea')
                form_data['fields'] = []
                for inp in inputs[:20]:  # Limit to 20 fields
                    field = {
                        'type': inp.get_attribute('type') or 'text',
                        'name': inp.get_attribute('name') or '',
                        'id': inp.get_attribute('id') or ''
                    }
                    form_data['fields'].append(field)
                
                forms.append(form_data)
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"Error extracting forms: {e}")
    
    return forms[:10]  # Limit to 10 forms


def _extract_scripts(page) -> List[Dict]:
    """Extract external script sources."""
    scripts = []
    try:
        script_elements = page.query_selector_all('script[src]')
        for script in script_elements:
            try:
                src = script.get_attribute('src')
                if src:
                    scripts.append({
                        'src': src,
                        'async': script.get_attribute('async') is not None,
                        'defer': script.get_attribute('defer') is not None
                    })
            except Exception:
                continue
    except Exception as e:
        logger.warning(f"Error extracting scripts: {e}")
    
    return scripts[:50]  # Limit to 50 scripts


def _extract_technologies(page, headers: Dict) -> List[str]:
    """Try to detect technologies used on the page."""
    technologies = []
    try:
        html = page.content().lower()
        
        # Check for common frameworks/libraries
        tech_patterns = {
            'jQuery': ['jquery', 'jquery.min.js'],
            'React': ['react.', 'react-dom', '__react'],
            'Vue.js': ['vue.', 'vue.min.js', '__vue__'],
            'Angular': ['ng-', 'angular.', 'ng-app'],
            'Bootstrap': ['bootstrap.', 'bootstrap.min.'],
            'Tailwind CSS': ['tailwind', 'tw-'],
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal.js', 'drupal.settings'],
            'Joomla': ['joomla', '/media/jui/'],
            'Shopify': ['shopify', 'cdn.shopify'],
            'Wix': ['wix.com', 'static.wixstatic'],
            'Squarespace': ['squarespace'],
            'Google Analytics': ['google-analytics', 'gtag', 'ga.js'],
            'Google Tag Manager': ['googletagmanager'],
            'Facebook Pixel': ['fbq(', 'facebook.net/en_US/fbevents'],
            'Cloudflare': ['cloudflare', '__cf_'],
            'reCAPTCHA': ['recaptcha', 'grecaptcha'],
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in html:
                    if tech not in technologies:
                        technologies.append(tech)
                    break
        
        # Check headers for server info
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'apache' in server:
            technologies.append('Apache')
        if 'cloudflare' in server:
            if 'Cloudflare' not in technologies:
                technologies.append('Cloudflare')
        
        x_powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in x_powered_by:
            technologies.append('PHP')
        if 'asp.net' in x_powered_by:
            technologies.append('ASP.NET')
        if 'express' in x_powered_by:
            technologies.append('Express.js')
        
    except Exception as e:
        logger.warning(f"Error detecting technologies: {e}")
    
    return technologies


@celery.task(bind=True, max_retries=2, soft_time_limit=120)
def scan_url(self, scan_id: str, url: str, user_id: str, options: Optional[Dict] = None):
    """
    Scan a URL using Playwright to capture screenshot and extract information.
    
    Args:
        scan_id: Unique scan ID
        url: URL to scan
        user_id: User ID who initiated the scan
        options: Optional configuration:
            - viewport_width: Browser viewport width (default 1920)
            - viewport_height: Browser viewport height (default 1080)
            - wait_time: Time to wait after page load in ms (default 2000)
            - full_page: Whether to capture full page screenshot (default False)
            - user_agent: Custom user agent string
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    
    es = ElasticsearchService()
    options = options or {}
    
    logger.info(f"[URLScan] Starting scan for: {url} (scan_id: {scan_id})")
    
    # Initialize scan document - use 'target' and 'timestamp' for consistency with other tools
    scan_doc = {
        'scan_id': scan_id,
        'user_id': user_id,
        'url': url,
        'target': url,  # Required for scan history display
        'status': 'processing',
        'tool': 'urlscan',
        'timestamp': datetime.utcnow().isoformat() + 'Z',  # Required for scan history display
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'updated_at': datetime.utcnow().isoformat() + 'Z'
    }
    
    try:
        es.index('scan_results', scan_id, scan_doc)
    except Exception as e:
        logger.warning(f"[URLScan] Could not save initial scan doc: {e}")
    
    result = {
        'scan_id': scan_id,
        'url': url,
        'success': False,
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }
    
    try:
        with sync_playwright() as p:
            # Launch browser
            browser = p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--single-process'
                ]
            )
            
            # Create context with custom viewport
            viewport_width = options.get('viewport_width', 1920)
            viewport_height = options.get('viewport_height', 1080)
            user_agent = options.get('user_agent', 
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            context = browser.new_context(
                viewport={'width': viewport_width, 'height': viewport_height},
                user_agent=user_agent,
                ignore_https_errors=True
            )
            
            page = context.new_page()
            
            # Collect response headers
            response_headers = {}
            def handle_response(response):
                nonlocal response_headers
                if response.url == url or response.url == page.url:
                    try:
                        response_headers = dict(response.headers)
                    except Exception:
                        pass
            
            page.on('response', handle_response)
            
            # Navigate to URL
            logger.info(f"[URLScan] Navigating to {url}")
            try:
                response = page.goto(url, wait_until='networkidle', timeout=60000)
                status_code = response.status if response else None
            except PlaywrightTimeout:
                logger.warning(f"[URLScan] Navigation timeout for {url}, continuing anyway")
                status_code = None
            
            # Wait additional time for dynamic content
            wait_time = options.get('wait_time', 2000)
            page.wait_for_timeout(wait_time)
            
            # Get final URL (after redirects)
            final_url = page.url
            logger.info(f"[URLScan] Final URL: {final_url}")
            
            # Take screenshot
            full_page = options.get('full_page', False)
            screenshot_bytes = page.screenshot(full_page=full_page, type='png')
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            logger.info(f"[URLScan] Screenshot captured ({len(screenshot_bytes)} bytes)")
            
            # Extract page data
            links = _extract_links_from_page(page)
            metadata = _extract_metadata(page)
            forms = _extract_forms(page)
            scripts = _extract_scripts(page)
            technologies = _extract_technologies(page, response_headers)
            
            # Categorize links
            internal_links = [l for l in links if l['type'] == 'internal']
            external_links = [l for l in links if l['type'] == 'external']
            email_links = [l for l in links if l['type'] == 'email']
            
            # Build result
            result.update({
                'success': True,
                'final_url': final_url,
                'status_code': status_code,
                'redirected': final_url != url,
                'screenshot': screenshot_base64,
                'screenshot_size': len(screenshot_bytes),
                'metadata': metadata,
                'links': {
                    'total': len(links),
                    'internal': internal_links[:100],  # Limit stored links
                    'external': external_links[:100],
                    'emails': email_links[:20],
                    'internal_count': len(internal_links),
                    'external_count': len(external_links),
                    'email_count': len(email_links)
                },
                'forms': forms,
                'scripts': scripts[:30],
                'technologies': technologies,
                'response_headers': dict(list(response_headers.items())[:50]),  # Limit headers
                'viewport': {
                    'width': viewport_width,
                    'height': viewport_height
                }
            })
            
            browser.close()
            logger.info(f"[URLScan] Scan completed successfully for {url}")
    
    except PlaywrightTimeout as e:
        logger.error(f"[URLScan] Timeout error for {url}: {e}")
        result['error'] = f'Page load timeout: {str(e)}'
        result['error_type'] = 'timeout'
        
    except Exception as e:
        logger.error(f"[URLScan] Error scanning {url}: {e}", exc_info=True)
        result['error'] = str(e)
        result['error_type'] = 'unknown'
    
    # Save result to Elasticsearch
    result['updated_at'] = datetime.utcnow().isoformat() + 'Z'
    scan_doc.update({
        'status': 'completed' if result.get('success') else 'failed',
        'success': result.get('success', False),
        'result': result,
        'updated_at': result['updated_at']
    })
    
    try:
        es.index('scan_results', scan_id, scan_doc)
        logger.info(f"[URLScan] Result saved to Elasticsearch (scan_id: {scan_id})")
    except Exception as e:
        logger.error(f"[URLScan] Failed to save result: {e}")
    
    return result


@celery.task(bind=True)
def get_urlscan_status(self, scan_id: str) -> Dict:
    """
    Get the status of a URL scan.
    
    Args:
        scan_id: Scan ID to check
        
    Returns:
        Scan status and result if available
    """
    es = ElasticsearchService()
    
    try:
        result = es.get('scan_results', scan_id)
        if result:
            doc = result['_source']
            return {
                'scan_id': scan_id,
                'status': doc.get('status', 'unknown'),
                'success': doc.get('success', False),
                'url': doc.get('url'),
                'result': doc.get('result'),
                'created_at': doc.get('created_at'),
                'updated_at': doc.get('updated_at')
            }
    except Exception as e:
        logger.error(f"[URLScan] Error getting scan status: {e}")
    
    return {
        'scan_id': scan_id,
        'status': 'not_found',
        'error': 'Scan not found'
    }
