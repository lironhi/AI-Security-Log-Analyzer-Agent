import httpx
import asyncio
from typing import Dict, Any, Optional
import redis
import json
from datetime import timedelta
from app.cache import cache

class IntelligenceProvider:
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client or cache.redis_client
        self.cache_ttl = timedelta(hours=24)
    
    async def ip(self, ip: str) -> Dict[str, Any]:
        """Get IP intelligence information"""
        cache_key = f"intel:ip:{ip}"
        
        # Check cache first
        if self.redis_client:
            cached = self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        
        # Simulate IP intelligence (replace with real API calls)
        intel_data = await self._fetch_ip_intel(ip)
        
        # Cache result
        if self.redis_client:
            self.redis_client.setex(
                cache_key,
                int(self.cache_ttl.total_seconds()),
                json.dumps(intel_data)
            )
        
        return intel_data
    
    async def _fetch_ip_intel(self, ip: str) -> Dict[str, Any]:
        """Fetch IP intelligence from various sources"""
        # Basic IP categorization logic
        intel = {
            'ip': ip,
            'reputation': 'unknown',
            'country': 'unknown',
            'asn': 'unknown',
            'is_tor': False,
            'is_vpn': False,
            'is_proxy': False,
            'threat_score': 0,
            'categories': [],
            'first_seen': None,
            'last_seen': None
        }
        
        # Simple heuristics for demo
        if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
            intel['reputation'] = 'internal'
            intel['categories'] = ['internal']
        elif self._is_suspicious_ip(ip):
            intel['reputation'] = 'suspicious'
            intel['threat_score'] = 75
            intel['categories'] = ['suspicious', 'scanning']
        else:
            intel['reputation'] = 'clean'
            intel['threat_score'] = 10
        
        return intel
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Simple suspicious IP detection"""
        suspicious_patterns = [
            # Common scanning IPs patterns
            '1.2.3.',
            '45.', 
            '185.',
            # Add more patterns as needed
        ]
        
        return any(ip.startswith(pattern) for pattern in suspicious_patterns)
    
    async def domain(self, domain: str) -> Dict[str, Any]:
        """Get domain intelligence information"""
        cache_key = f"intel:domain:{domain}"
        
        if self.redis_client:
            cached = self.redis_client.get(cache_key)
            if cached:
                return json.loads(cached)
        
        intel_data = {
            'domain': domain,
            'reputation': 'unknown',
            'category': 'unknown',
            'threat_score': 0,
            'is_dga': False,
            'creation_date': None
        }
        
        if self.redis_client:
            self.redis_client.setex(
                cache_key,
                int(self.cache_ttl.total_seconds()),
                json.dumps(intel_data)
            )
        
        return intel_data

intel_provider = IntelligenceProvider()