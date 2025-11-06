import asyncio
import json
from typing import Dict, Any, List
from datetime import datetime
from app.models import ActionResult
from loguru import logger

class SecurityActions:
    def __init__(self):
        self.blocked_ips = set()
        self.rate_limits = {}
        self.action_log = []
    
    async def block_ip(self, ip: str, reason: str = "") -> ActionResult:
        """Block an IP address"""
        try:
            # Simulate firewall rule addition
            self.blocked_ips.add(ip)
            
            result = ActionResult(
                action_type="block_ip",
                target=ip,
                success=True,
                message=f"Successfully blocked IP {ip}. Reason: {reason}"
            )
            
            self.action_log.append(result)
            logger.info(f"Blocked IP {ip}: {reason}")
            
            return result
        
        except Exception as e:
            result = ActionResult(
                action_type="block_ip",
                target=ip,
                success=False,
                message=f"Failed to block IP {ip}: {str(e)}"
            )
            
            self.action_log.append(result)
            logger.error(f"Failed to block IP {ip}: {e}")
            
            return result
    
    async def unblock_ip(self, ip: str) -> ActionResult:
        """Unblock an IP address"""
        try:
            self.blocked_ips.discard(ip)
            
            result = ActionResult(
                action_type="unblock_ip",
                target=ip,
                success=True,
                message=f"Successfully unblocked IP {ip}"
            )
            
            self.action_log.append(result)
            logger.info(f"Unblocked IP {ip}")
            
            return result
        
        except Exception as e:
            result = ActionResult(
                action_type="unblock_ip",
                target=ip,
                success=False,
                message=f"Failed to unblock IP {ip}: {str(e)}"
            )
            
            self.action_log.append(result)
            return result
    
    async def rate_limit_ip(self, ip: str, requests_per_minute: int = 10) -> ActionResult:
        """Apply rate limiting to an IP"""
        try:
            self.rate_limits[ip] = {
                'limit': requests_per_minute,
                'applied_at': datetime.now()
            }
            
            result = ActionResult(
                action_type="rate_limit",
                target=ip,
                success=True,
                message=f"Applied rate limit of {requests_per_minute} req/min to IP {ip}"
            )
            
            self.action_log.append(result)
            logger.info(f"Rate limited IP {ip}: {requests_per_minute} req/min")
            
            return result
        
        except Exception as e:
            result = ActionResult(
                action_type="rate_limit",
                target=ip,
                success=False,
                message=f"Failed to rate limit IP {ip}: {str(e)}"
            )
            
            self.action_log.append(result)
            return result
    
    async def reset_tokens(self, user: str) -> ActionResult:
        """Reset authentication tokens for a user"""
        try:
            # Simulate token invalidation
            result = ActionResult(
                action_type="reset_tokens",
                target=user,
                success=True,
                message=f"Successfully reset tokens for user {user}"
            )
            
            self.action_log.append(result)
            logger.info(f"Reset tokens for user {user}")
            
            return result
        
        except Exception as e:
            result = ActionResult(
                action_type="reset_tokens",
                target=user,
                success=False,
                message=f"Failed to reset tokens for user {user}: {str(e)}"
            )
            
            self.action_log.append(result)
            return result
    
    def is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is blocked"""
        return ip in self.blocked_ips
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return list(self.blocked_ips)
    
    def get_action_history(self) -> List[ActionResult]:
        """Get action history"""
        return self.action_log.copy()

actions = SecurityActions()