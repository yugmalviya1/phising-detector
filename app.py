from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import re
from urllib.parse import urlparse

app = Flask(__name__, static_folder='.')
CORS(app)

def extract_url_features(url):
    """Extract features from URL to detect phishing"""
    features = {}
    
    # Parse URL
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
    except:
        return None
    
    # Feature 1: URL Length (phishing URLs tend to be longer)
    features['url_length'] = len(url)
    features['long_url'] = len(url) > 54
    
    # Feature 2: Number of dots in domain
    features['dots_in_domain'] = domain.count('.')
    
    # Feature 3: Has IP address instead of domain
    features['has_ip'] = bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain))
    
    # Feature 4: Has @ symbol (often used in phishing)
    features['has_at'] = '@' in url
    
    # Feature 5: Has double slash in path
    features['double_slash_in_path'] = '//' in path
    
    # Feature 6: Number of subdomains (more subdomains = more suspicious)
    features['subdomain_count'] = domain.count('.') - 1 if domain.count('.') > 0 else 0
    features['many_subdomains'] = features['subdomain_count'] > 3
    
    # Feature 7: Has suspicious keywords
    suspicious_keywords = ['login', 'verify', 'account', 'update', 'secure', 'banking', 
                          'confirm', 'signin', 'ebayisapi', 'webscr', 'paypal', 'password',
                          'credential', 'suspended', 'locked', 'unusual', 'click', 'urgent']
    features['has_suspicious_keyword'] = any(keyword in full_url for keyword in suspicious_keywords)
    
    # Feature 8: Has hyphen in domain (common in phishing)
    features['has_hyphen'] = '-' in domain
    features['multiple_hyphens'] = domain.count('-') > 1
    
    # Feature 9: HTTPS check
    features['is_https'] = parsed.scheme == 'https'
    
    # Feature 10: Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click', '.link']
    features['suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
    
    # Feature 11: Brand impersonation patterns
    brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 
              'instagram', 'twitter', 'linkedin', 'ebay', 'bank', 'wells', 'chase', 'citi']
    features['brand_in_subdomain'] = any(brand in domain.split('.')[0] for brand in brands if '.' in domain)
    
    # Feature 12: Shortened URL services
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']
    features['is_shortened'] = any(short in domain for short in shorteners)
    
    # Feature 13: Has port number (unusual for legitimate sites)
    features['has_port'] = ':' in domain and not domain.startswith('[')
    
    # Feature 14: Excessive special characters
    special_chars = url.count('-') + url.count('_') + url.count('?') + url.count('=') + url.count('&')
    features['many_special_chars'] = special_chars > 5
    
    # Feature 15: Suspicious patterns
    features['has_redirect'] = 'redirect' in full_url or 'redir' in full_url
    features['has_hex_chars'] = bool(re.search(r'%[0-9a-f]{2}', full_url))
    
    return features

def predict_phishing(url):
    """Enhanced rule-based phishing detection"""
    features = extract_url_features(url)
    
    if features is None:
        return {'error': 'Invalid URL'}
    
    # Calculate risk score with weighted features
    risk_score = 0
    risk_factors = []
    
    # Critical indicators (high weight)
    if features['has_ip']:
        risk_score += 5
        risk_factors.append('Uses IP address instead of domain name')
    
    if features['has_at']:
        risk_score += 5
        risk_factors.append('Contains @ symbol (URL obfuscation)')
    
    if features['brand_in_subdomain']:
        risk_score += 4
        risk_factors.append('Brand name in subdomain (possible impersonation)')
    
    if features['suspicious_tld']:
        risk_score += 4
        risk_factors.append('Suspicious top-level domain')
    
    # High risk indicators
    if features['long_url']:
        risk_score += 3
        risk_factors.append('Unusually long URL')
    
    if features['many_subdomains']:
        risk_score += 3
        risk_factors.append('Too many subdomains')
    
    if features['double_slash_in_path']:
        risk_score += 3
        risk_factors.append('Double slash in path')
    
    if features['has_suspicious_keyword']:
        risk_score += 3
        risk_factors.append('Contains suspicious keywords')
    
    if features['is_shortened']:
        risk_score += 3
        risk_factors.append('URL shortening service detected')
    
    # Medium risk indicators
    if features['multiple_hyphens']:
        risk_score += 2
        risk_factors.append('Multiple hyphens in domain')
    
    if features['has_port']:
        risk_score += 2
        risk_factors.append('Non-standard port number')
    
    if features['many_special_chars']:
        risk_score += 2
        risk_factors.append('Excessive special characters')
    
    if features['has_redirect']:
        risk_score += 2
        risk_factors.append('Contains redirect patterns')
    
    if features['has_hex_chars']:
        risk_score += 1
        risk_factors.append('Contains encoded characters')
    
    # Low risk indicators
    if features['has_hyphen']:
        risk_score += 1
        risk_factors.append('Contains hyphen in domain')
    
    if not features['is_https']:
        risk_score += 1
        risk_factors.append('Not using HTTPS')
    
    if features['dots_in_domain'] > 4:
        risk_score += 2
        risk_factors.append('Too many dots in domain')
    
    # Determine result with more aggressive thresholds
    max_score = 35
    
    if risk_score >= 10:
        return {
            'prediction': 'phishing',
            'risk_score': risk_score,
            'max_score': max_score,
            'message': 'This URL appears to be a PHISHING link. Do not click or enter any information!',
            'confidence': 'High Risk',
            'risk_factors': risk_factors
        }
    elif risk_score >= 5:
        return {
            'prediction': 'suspicious',
            'risk_score': risk_score,
            'max_score': max_score,
            'message': 'This URL looks SUSPICIOUS. Proceed with extreme caution!',
            'confidence': 'Medium Risk',
            'risk_factors': risk_factors
        }
    else:
        return {
            'prediction': 'legitimate',
            'risk_score': risk_score,
            'max_score': max_score,
            'message': 'This URL appears to be relatively safe, but always verify the source.',
            'confidence': 'Low Risk',
            'risk_factors': risk_factors if risk_factors else ['No major red flags detected']
        }

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get URL from form data
        url = request.form.get('name')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Validate URL format
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL must start with http:// or https://'}), 400
        
        # Get prediction
        result = predict_phishing(url)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8000)
