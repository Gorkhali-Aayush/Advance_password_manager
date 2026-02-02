"""
Password Policy

Defines and enforces password strength requirements.
Centralized policy for consistent security standards.
"""

import re
import string
from typing import List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class PasswordStrength(Enum):
    """Password strength levels."""
    VERY_WEAK = 0
    WEAK = 1
    FAIR = 2
    STRONG = 3
    VERY_STRONG = 4


@dataclass
class PolicyViolation:
    """
    Represents a policy violation.
    
    Attributes:
        rule: Name of the violated rule
        message: User-friendly message
    """
    rule: str
    message: str


@dataclass
class PasswordPolicyConfig:
    """
    Configuration for password policy.
    
    Modify these values to change password requirements.
    """
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    min_uppercase: int = 1
    min_lowercase: int = 1
    min_digits: int = 1
    min_special: int = 1
    disallow_common: bool = True
    disallow_sequences: bool = True
    max_consecutive_chars: int = 3


class PasswordPolicy:
    """
    Enforces password strength requirements.
    
    Features:
    - Configurable rules
    - Detailed violation reporting
    - Strength scoring
    - Common password detection
    
    Why this exists:
    - Security: Enforce strong passwords
    - Centralized: Single source of truth
    - Testable: Easy to verify behavior
    """
    
    # Common passwords to reject (Very Weak - instantly cracked)
    COMMON_PASSWORDS = {
        # Top common passwords
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'password1', 'password123', 'admin', 'letmein', 'welcome',
        'monkey', '1234567', '12345', '1234567890', 'dragon',
        'master', 'login', 'passw0rd', 'hello', 'charlie',
        '123456789', '111111', 'iloveyou', 'sunshine', 'princess',
        'football', 'baseball', 'trustno1', 'superman', 'batman',
        'shadow', 'michael', 'jennifer', 'hunter', 'ashley',
        '654321', 'access', 'joshua', 'mustang', 'nicole',
        # Simple patterns
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qazwsx',
        '000000', '11111111', 'aaaaaa', 'secret', 'test',
        'guest', 'root', 'user', 'demo', 'sample'
    }
    
    # Weak password patterns (simple substitutions, common phrases)
    WEAK_PATTERNS = [
        r'^[a-z]+\d{1,4}$',  # word + few numbers: monkey123
        r'^[A-Z][a-z]+\d{1,4}$',  # Capitalized + numbers: Monkey123
        r'^[a-z]+!$',  # word + exclamation: password!
        r'^[A-Z][a-z]+!$',  # Capitalized + exclamation: Password!
        r'^\d{10,}$',  # Only long numbers: 1234567890
        r'^[Ww]elcome\d*$',  # Welcome patterns
        r'^[Pp]assword.{0,3}$',  # Password variations
        r'^[Aa]dmin.{0,3}$',  # Admin variations
    ]
    
    # Keyboard sequences to detect
    SEQUENCES = [
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        'qwerty', 'asdfgh', 'zxcvbn',
        '123456789', '987654321',
        'abcdefghij', 'jihgfedcba',
        'qazwsx', 'wsxedc', 'edcrfv'
    ]
    
    def __init__(self, config: Optional[PasswordPolicyConfig] = None):
        """
        Initialize password policy.
        
        Args:
            config: Custom policy configuration
        """
        self._config = config or PasswordPolicyConfig()
    
    @property
    def config(self) -> PasswordPolicyConfig:
        """Get the policy configuration."""
        return self._config
    
    def validate(self, password: str) -> Tuple[bool, List[PolicyViolation]]:
        """
        Validate a password against the policy.
        
        Args:
            password: The password to validate
            
        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        violations = []
        
        # Length checks
        if len(password) < self._config.min_length:
            violations.append(PolicyViolation(
                rule="min_length",
                message=f"Password must be at least {self._config.min_length} characters"
            ))
        
        if len(password) > self._config.max_length:
            violations.append(PolicyViolation(
                rule="max_length",
                message=f"Password must not exceed {self._config.max_length} characters"
            ))
        
        # Character type checks
        if self._config.require_uppercase:
            uppercase_count = sum(1 for c in password if c.isupper())
            if uppercase_count < self._config.min_uppercase:
                violations.append(PolicyViolation(
                    rule="uppercase",
                    message=f"Password must contain at least {self._config.min_uppercase} uppercase letter(s)"
                ))
        
        if self._config.require_lowercase:
            lowercase_count = sum(1 for c in password if c.islower())
            if lowercase_count < self._config.min_lowercase:
                violations.append(PolicyViolation(
                    rule="lowercase",
                    message=f"Password must contain at least {self._config.min_lowercase} lowercase letter(s)"
                ))
        
        if self._config.require_digits:
            digit_count = sum(1 for c in password if c.isdigit())
            if digit_count < self._config.min_digits:
                violations.append(PolicyViolation(
                    rule="digits",
                    message=f"Password must contain at least {self._config.min_digits} digit(s)"
                ))
        
        if self._config.require_special:
            special_count = sum(1 for c in password if c in string.punctuation)
            if special_count < self._config.min_special:
                violations.append(PolicyViolation(
                    rule="special",
                    message=f"Password must contain at least {self._config.min_special} special character(s)"
                ))
        
        # Common password check
        if self._config.disallow_common:
            if password.lower() in self.COMMON_PASSWORDS:
                violations.append(PolicyViolation(
                    rule="common_password",
                    message="Password is too common"
                ))
        
        # Sequence check
        if self._config.disallow_sequences:
            if self._contains_sequence(password):
                violations.append(PolicyViolation(
                    rule="sequence",
                    message="Password contains a keyboard sequence"
                ))
        
        # Consecutive character check
        if self._has_consecutive_chars(password):
            violations.append(PolicyViolation(
                rule="consecutive",
                message=f"Password contains more than {self._config.max_consecutive_chars} consecutive identical characters"
            ))
        
        return (len(violations) == 0, violations)
    
    def _contains_sequence(self, password: str) -> bool:
        """Check if password contains keyboard sequences."""
        password_lower = password.lower()
        
        for sequence in self.SEQUENCES:
            # Check forward sequence
            for i in range(len(sequence) - 3):
                if sequence[i:i+4] in password_lower:
                    return True
            
            # Check reverse sequence
            reversed_seq = sequence[::-1]
            for i in range(len(reversed_seq) - 3):
                if reversed_seq[i:i+4] in password_lower:
                    return True
        
        return False
    
    def _has_consecutive_chars(self, password: str) -> bool:
        """Check for too many consecutive identical characters."""
        if len(password) < self._config.max_consecutive_chars + 1:
            return False
        
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count > self._config.max_consecutive_chars:
                    return True
            else:
                count = 1
        
        return False
    
    def calculate_strength(self, password: str) -> Tuple[PasswordStrength, int]:
        """
        Calculate password strength score based on industry standards.
        
        Strength Levels:
        - VERY_WEAK: Instantly cracked (common passwords, <8 chars, predictable)
        - WEAK: Minutes to hours to crack (simple substitutions, common patterns)
        - FAIR (MODERATE): 8-12 chars with mixed case, numbers, symbols
        - STRONG: 16+ chars, passphrase or random characters
        - VERY_STRONG: 20+ chars, completely random, all character types
        
        Args:
            password: The password to evaluate
            
        Returns:
            Tuple of (strength_level, score_percentage)
        """
        password_lower = password.lower()
        length = len(password)
        
        # Character type checks
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)
        char_types = sum([has_lower, has_upper, has_digit, has_special])
        
        # Pattern checks
        is_common = password_lower in self.COMMON_PASSWORDS
        has_sequence = self._contains_sequence(password)
        has_consecutive = self._has_consecutive_chars(password)
        is_weak_pattern = self._matches_weak_pattern(password)
        
        # Unique character ratio
        unique_ratio = len(set(password)) / max(1, length)
        
        # ========== VERY WEAK ==========
        # Instantly cracked: common passwords, <8 chars, predictable sequences
        if is_common:
            return (PasswordStrength.VERY_WEAK, 5)
        
        if length < 8:
            return (PasswordStrength.VERY_WEAK, max(5, length * 2))
        
        if has_sequence and length < 12:
            return (PasswordStrength.VERY_WEAK, 15)
        
        # Only one character type and short
        if char_types == 1 and length < 12:
            return (PasswordStrength.VERY_WEAK, 15)
        
        # ========== WEAK ==========
        # Minutes to hours: simple substitutions, common patterns
        if is_weak_pattern:
            return (PasswordStrength.WEAK, 25)
        
        if length < 10 and char_types < 3:
            return (PasswordStrength.WEAK, 30)
        
        if has_consecutive and length < 12:
            return (PasswordStrength.WEAK, 30)
        
        # Simple structure: Word + numbers only
        if length < 12 and char_types == 2:
            return (PasswordStrength.WEAK, 35)
        
        # ========== MODERATE (FAIR) ==========
        # 8-12 chars with mix of uppercase/lowercase and numbers/symbols
        if length >= 8 and length < 16:
            if char_types >= 3:
                score = 45 + (length - 8) * 2 + char_types * 2
                return (PasswordStrength.FAIR, min(score, 59))
            elif char_types >= 2:
                score = 40 + (length - 8) * 2
                return (PasswordStrength.FAIR, min(score, 55))
        
        # ========== STRONG ==========
        # 16+ chars, passphrase or random characters
        if length >= 16 and length < 20:
            if char_types >= 3:
                score = 70 + char_types * 2 + int(unique_ratio * 10)
                return (PasswordStrength.STRONG, min(score, 85))
            elif char_types >= 2:
                score = 65 + int(unique_ratio * 10)
                return (PasswordStrength.STRONG, min(score, 79))
        
        # ========== VERY STRONG ==========
        # 20+ chars, completely random, all character types
        if length >= 20:
            if char_types == 4 and unique_ratio >= 0.6:
                score = 95 + int(unique_ratio * 5)
                return (PasswordStrength.VERY_STRONG, min(score, 100))
            elif char_types >= 3:
                score = 85 + char_types * 2 + int(unique_ratio * 5)
                return (PasswordStrength.VERY_STRONG, min(score, 95))
            else:
                score = 80 + int(unique_ratio * 10)
                return (PasswordStrength.STRONG, min(score, 89))
        
        # Default: Calculate based on factors
        score = 0
        score += min(25, length * 1.5)  # Length contribution
        score += char_types * 10  # Character variety
        score += unique_ratio * 20  # Uniqueness
        
        if has_sequence:
            score -= 10
        if has_consecutive:
            score -= 5
        
        score = min(100, max(0, int(score)))
        
        # Map score to strength
        if score < 20:
            strength = PasswordStrength.VERY_WEAK
        elif score < 40:
            strength = PasswordStrength.WEAK
        elif score < 60:
            strength = PasswordStrength.FAIR
        elif score < 80:
            strength = PasswordStrength.STRONG
        else:
            strength = PasswordStrength.VERY_STRONG
        
        return (strength, score)
    
    def _matches_weak_pattern(self, password: str) -> bool:
        """Check if password matches weak patterns."""
        for pattern in self.WEAK_PATTERNS:
            if re.match(pattern, password):
                return True
        return False
    
    def get_strength_feedback(self, password: str) -> List[str]:
        """
        Get suggestions to improve password strength.
        
        Args:
            password: The password to evaluate
            
        Returns:
            List of improvement suggestions
        """
        suggestions = []
        length = len(password)
        
        # Length suggestions
        if length < 8:
            suggestions.append("⚠️ Too short! Use at least 8 characters")
        elif length < 12:
            suggestions.append("Consider using 12+ characters for moderate security")
        elif length < 16:
            suggestions.append("Use 16+ characters for strong security")
        elif length < 20:
            suggestions.append("Use 20+ characters for maximum security")
        
        # Character type suggestions
        if not any(c.isupper() for c in password):
            suggestions.append("Add uppercase letters (A-Z)")
        
        if not any(c.islower() for c in password):
            suggestions.append("Add lowercase letters (a-z)")
        
        if not any(c.isdigit() for c in password):
            suggestions.append("Add numbers (0-9)")
        
        if not any(c in string.punctuation for c in password):
            suggestions.append("Add special characters (!@#$%^&*)")
        
        # Uniqueness suggestion
        unique_ratio = len(set(password)) / max(1, length)
        if unique_ratio < 0.5:
            suggestions.append("Use more unique characters (avoid repetition)")
        
        # Pattern warnings
        if self._contains_sequence(password):
            suggestions.append("⚠️ Avoid keyboard sequences (qwerty, 12345)")
        
        if password.lower() in self.COMMON_PASSWORDS:
            suggestions.append("⚠️ This is a commonly used password!")
        
        if self._matches_weak_pattern(password):
            suggestions.append("⚠️ Avoid simple patterns like Word123 or Password!")
        
        if self._has_consecutive_chars(password):
            suggestions.append("Avoid repeating the same character")
        
        # Positive feedback for strong passwords
        if length >= 16 and not suggestions:
            suggestions.append("✅ Consider using a passphrase (random unrelated words)")
        
        if length >= 20 and unique_ratio >= 0.6:
            char_types = sum([
                any(c.isupper() for c in password),
                any(c.islower() for c in password),
                any(c.isdigit() for c in password),
                any(c in string.punctuation for c in password)
            ])
            if char_types == 4:
                suggestions = ["✅ Excellent! This password is very strong"]
        
        return suggestions
    
    def generate_password_hint(self) -> str:
        """
        Generate a hint for password requirements.
        
        Returns:
            Human-readable requirements string
        """
        parts = [f"At least {self._config.min_length} characters"]
        
        if self._config.require_uppercase:
            parts.append(f"{self._config.min_uppercase}+ uppercase")
        if self._config.require_lowercase:
            parts.append(f"{self._config.min_lowercase}+ lowercase")
        if self._config.require_digits:
            parts.append(f"{self._config.min_digits}+ number(s)")
        if self._config.require_special:
            parts.append(f"{self._config.min_special}+ special character(s)")
        
        return ", ".join(parts)


# Default policy instance
_default_policy: Optional[PasswordPolicy] = None


def get_password_policy() -> PasswordPolicy:
    """
    Get the default password policy instance.
    
    Returns:
        PasswordPolicy instance
    """
    global _default_policy
    if _default_policy is None:
        _default_policy = PasswordPolicy()
    return _default_policy
