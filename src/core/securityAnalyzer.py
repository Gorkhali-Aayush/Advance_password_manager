"""
Advanced Security Analyzer

Comprehensive password security analysis with custom algorithms.
Features:
- Custom strength scoring algorithm (not using built-in functions)
- Entropy calculation in bits
- Pattern detection using sliding window
- Priority queue for weak password sorting
- Age-based risk analysis
- Dictionary attack simulation
"""

import math
import heapq
import string
import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


# ============ Data Classes ============

@dataclass
class PasswordAnalysis:
    """Complete analysis of a single password."""
    credential_id: int
    site_name: str
    username: str
    
    # Strength metrics
    strength_score: int  # 0-100
    strength_category: str  # Very Weak, Weak, Moderate, Strong, Very Strong
    
    # Entropy
    entropy_bits: float
    entropy_rating: str
    
    # Issues found
    issues: List[str] = field(default_factory=list)
    patterns_found: List[str] = field(default_factory=list)
    
    # Age info
    password_age_days: int = 0
    is_expired: bool = False
    
    # Risk score (higher = worse)
    risk_score: float = 0.0
    
    def __lt__(self, other):
        """For priority queue - higher risk comes first."""
        return self.risk_score > other.risk_score


@dataclass
class SecurityReport:
    """Complete security report for the vault."""
    timestamp: datetime
    total_credentials: int
    
    # Overall scores
    security_score: float  # 0-100
    average_strength: float
    average_entropy: float
    
    # Distributions
    strength_distribution: Dict[str, int]
    age_distribution: Dict[str, int]
    
    # Issues
    weak_passwords: List[PasswordAnalysis]
    reused_passwords: List[Tuple[str, List[str]]]  # (hash_prefix, [credential_ids])
    expired_passwords: List[PasswordAnalysis]
    pattern_passwords: List[PasswordAnalysis]
    
    # Recommendations
    recommendations: List[Dict[str, Any]]


# ============ Priority Queue for Weak Passwords ============

class WeakPasswordQueue:
    """
    Priority Queue implementation for weak passwords.
    
    Uses a min-heap where priority is based on risk score.
    Higher risk passwords are retrieved first.
    
    Time Complexity:
    - Insert: O(log n)
    - Get highest risk: O(log n)
    - Peek: O(1)
    """
    
    def __init__(self):
        """Initialize empty priority queue."""
        self._heap: List[PasswordAnalysis] = []
        self._size = 0
    
    def push(self, analysis: PasswordAnalysis) -> None:
        """
        Add a password analysis to the queue.
        
        Args:
            analysis: Password analysis to add
        """
        # Use negative risk for max-heap behavior
        heapq.heappush(self._heap, analysis)
        self._size += 1
    
    def pop(self) -> Optional[PasswordAnalysis]:
        """
        Remove and return the highest-risk password.
        
        Returns:
            PasswordAnalysis with highest risk, or None if empty
        """
        if self._heap:
            self._size -= 1
            return heapq.heappop(self._heap)
        return None
    
    def peek(self) -> Optional[PasswordAnalysis]:
        """
        View the highest-risk password without removing.
        
        Returns:
            PasswordAnalysis with highest risk, or None if empty
        """
        return self._heap[0] if self._heap else None
    
    def get_all_sorted(self) -> List[PasswordAnalysis]:
        """
        Get all items sorted by risk (highest first).
        
        Returns:
            Sorted list of password analyses
        """
        return sorted(self._heap, key=lambda x: x.risk_score, reverse=True)
    
    def __len__(self) -> int:
        return self._size
    
    def is_empty(self) -> bool:
        return self._size == 0


# ============ Security Analyzer ============

class SecurityAnalyzer:
    """
    Advanced security analyzer with custom algorithms.
    
    Implements:
    1. Custom strength scoring (no built-in functions)
    2. Entropy calculation in bits
    3. Pattern detection using sliding window
    4. Age-based risk assessment
    5. Dictionary attack simulation
    """
    
    # Common password dictionary for detection
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'master', 'dragon', 'letmein', 'login', 'admin', 'welcome',
        'password1', 'password123', '12345', '1234567', '1234567890',
        'passw0rd', 'sunshine', 'princess', 'football', 'iloveyou',
        'trustno1', 'superman', 'batman', 'starwars', 'shadow',
        'michael', 'jennifer', 'ashley', 'charlie', 'jordan'
    }
    
    # Common dictionary words (for basic detection)
    DICTIONARY_WORDS = {
        'hello', 'world', 'computer', 'secret', 'private', 'access',
        'system', 'network', 'server', 'database', 'security', 'user',
        'account', 'manager', 'office', 'company', 'business', 'home',
        'family', 'love', 'money', 'power', 'control', 'master'
    }
    
    # Keyboard patterns for detection
    KEYBOARD_ROWS = [
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
        '1234567890', '!@#$%^&*()'
    ]
    
    # Password age thresholds (days)
    AGE_WARNING = 90
    AGE_EXPIRED = 180
    
    def __init__(self):
        """Initialize the security analyzer."""
        self._weak_queue = WeakPasswordQueue()
        self._last_analysis: Optional[SecurityReport] = None
    
    # ============ Main Analysis ============
    
    def analyze_password(self, password: str, credential_id: int,
                        site_name: str, username: str,
                        created_at: Optional[datetime] = None) -> PasswordAnalysis:
        """
        Perform comprehensive analysis of a single password.
        
        This uses CUSTOM ALGORITHMS, not built-in functions.
        
        Args:
            password: The password to analyze
            credential_id: ID of the credential
            site_name: Name of the site
            username: Username for the credential
            created_at: When the password was created
            
        Returns:
            Complete PasswordAnalysis
        """
        issues = []
        patterns = []
        
        # 1. Calculate strength using custom algorithm
        strength_score, strength_details = self._calculate_strength_custom(password)
        strength_category = self._score_to_category(strength_score)
        issues.extend(strength_details.get('issues', []))
        
        # 2. Calculate entropy
        entropy_bits = self._calculate_entropy(password)
        entropy_rating = self._entropy_to_rating(entropy_bits)
        
        # 3. Detect patterns using sliding window
        detected_patterns = self._detect_patterns_sliding_window(password)
        if detected_patterns:
            patterns.extend(detected_patterns)
            issues.append(f"Contains {len(detected_patterns)} pattern(s)")
        
        # 4. Check dictionary words
        dict_words = self._detect_dictionary_words(password)
        if dict_words:
            issues.append(f"Contains dictionary word(s): {', '.join(dict_words[:3])}")
        
        # 5. Check common passwords
        if password.lower() in self.COMMON_PASSWORDS:
            issues.append("Password is in common password list")
        
        # 6. Calculate age
        age_days = 0
        is_expired = False
        if created_at:
            age_days = (datetime.now() - created_at).days
            if age_days > self.AGE_EXPIRED:
                is_expired = True
                issues.append(f"Password is {age_days} days old (expired)")
            elif age_days > self.AGE_WARNING:
                issues.append(f"Password is {age_days} days old (consider changing)")
        
        # 7. Calculate overall risk score
        risk_score = self._calculate_risk_score(
            strength_score, entropy_bits, len(patterns),
            len(dict_words), is_expired, password.lower() in self.COMMON_PASSWORDS
        )
        
        return PasswordAnalysis(
            credential_id=credential_id,
            site_name=site_name,
            username=username,
            strength_score=strength_score,
            strength_category=strength_category,
            entropy_bits=entropy_bits,
            entropy_rating=entropy_rating,
            issues=issues,
            patterns_found=patterns,
            password_age_days=age_days,
            is_expired=is_expired,
            risk_score=risk_score
        )
    
    # ============ Custom Strength Algorithm ============
    
    def _calculate_strength_custom(self, password: str) -> Tuple[int, Dict]:
        """
        Custom password strength calculation algorithm.
        
        This does NOT use any built-in strength checking functions.
        It manually analyzes:
        - Length (weighted score)
        - Character diversity (manual counting)
        - Repetition (sliding window)
        - Predictability (pattern matching)
        
        Args:
            password: Password to analyze
            
        Returns:
            Tuple of (score 0-100, details dict)
        """
        score = 0
        details = {'issues': [], 'breakdown': {}}
        length = len(password)
        
        # === Length Analysis (max 30 points) ===
        # Custom scoring: 2 points per character up to 15 chars
        length_score = min(30, length * 2)
        if length < 8:
            details['issues'].append("Password too short (< 8 chars)")
            length_score = max(0, length_score - 10)
        elif length < 12:
            details['issues'].append("Password could be longer (< 12 chars)")
        details['breakdown']['length'] = length_score
        score += length_score
        
        # === Character Diversity Analysis (max 25 points) ===
        # Manual character type counting
        lowercase_count = 0
        uppercase_count = 0
        digit_count = 0
        special_count = 0
        
        for char in password:
            ascii_val = ord(char)
            if 97 <= ascii_val <= 122:  # a-z
                lowercase_count += 1
            elif 65 <= ascii_val <= 90:  # A-Z
                uppercase_count += 1
            elif 48 <= ascii_val <= 57:  # 0-9
                digit_count += 1
            elif 32 <= ascii_val <= 126:  # Other printable
                special_count += 1
        
        diversity_score = 0
        type_count = 0
        
        if lowercase_count > 0:
            diversity_score += 6
            type_count += 1
        else:
            details['issues'].append("Missing lowercase letters")
            
        if uppercase_count > 0:
            diversity_score += 6
            type_count += 1
        else:
            details['issues'].append("Missing uppercase letters")
            
        if digit_count > 0:
            diversity_score += 6
            type_count += 1
        else:
            details['issues'].append("Missing numbers")
            
        if special_count > 0:
            diversity_score += 7
            type_count += 1
        else:
            details['issues'].append("Missing special characters")
        
        details['breakdown']['diversity'] = diversity_score
        score += diversity_score
        
        # === Uniqueness Analysis (max 20 points) ===
        # Count unique characters manually
        unique_chars = set()
        for char in password:
            unique_chars.add(char)
        
        unique_ratio = len(unique_chars) / max(1, length)
        uniqueness_score = int(unique_ratio * 20)
        
        if unique_ratio < 0.5:
            details['issues'].append("Too many repeated characters")
        
        details['breakdown']['uniqueness'] = uniqueness_score
        score += uniqueness_score
        
        # === Consecutive Character Analysis (max 15 points) ===
        consecutive_score = 15
        max_consecutive = 1
        current_consecutive = 1
        
        for i in range(1, length):
            if password[i] == password[i-1]:
                current_consecutive += 1
                max_consecutive = max(max_consecutive, current_consecutive)
            else:
                current_consecutive = 1
        
        if max_consecutive >= 3:
            consecutive_score -= (max_consecutive - 2) * 3
            details['issues'].append(f"Has {max_consecutive} consecutive identical chars")
        
        consecutive_score = max(0, consecutive_score)
        details['breakdown']['no_consecutive'] = consecutive_score
        score += consecutive_score
        
        # === Sequential Pattern Detection (max 10 points) ===
        sequence_score = 10
        
        # Check for ascending/descending sequences
        ascending = 0
        descending = 0
        
        for i in range(1, length):
            diff = ord(password[i]) - ord(password[i-1])
            if diff == 1:
                ascending += 1
            elif diff == -1:
                descending += 1
        
        if ascending >= 3:
            sequence_score -= 5
            details['issues'].append("Contains ascending sequence")
        if descending >= 3:
            sequence_score -= 5
            details['issues'].append("Contains descending sequence")
        
        sequence_score = max(0, sequence_score)
        details['breakdown']['no_sequences'] = sequence_score
        score += sequence_score
        
        # Clamp final score
        score = max(0, min(100, score))
        
        return score, details
    
    def _score_to_category(self, score: int) -> str:
        """Convert numeric score to category."""
        if score < 20:
            return "Very Weak"
        elif score < 40:
            return "Weak"
        elif score < 60:
            return "Moderate"
        elif score < 80:
            return "Strong"
        else:
            return "Very Strong"
    
    # ============ Entropy Calculation ============
    
    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate Shannon entropy of password in bits.
        
        Entropy = log2(charset_size) * password_length
        
        This measures the theoretical randomness/unpredictability.
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy in bits
        """
        if not password:
            return 0.0
        
        # Determine character set size
        charset_size = 0
        has_lower = False
        has_upper = False
        has_digit = False
        has_special = False
        
        for char in password:
            ascii_val = ord(char)
            if 97 <= ascii_val <= 122 and not has_lower:
                has_lower = True
                charset_size += 26  # a-z
            elif 65 <= ascii_val <= 90 and not has_upper:
                has_upper = True
                charset_size += 26  # A-Z
            elif 48 <= ascii_val <= 57 and not has_digit:
                has_digit = True
                charset_size += 10  # 0-9
            elif 32 <= ascii_val <= 126 and not has_special:
                has_special = True
                charset_size += 32  # Special chars
        
        if charset_size == 0:
            charset_size = 1
        
        # Calculate entropy: H = L * log2(N)
        # Where L = length, N = charset size
        entropy = len(password) * math.log2(charset_size)
        
        # Adjust for repeated characters (reduces entropy)
        unique_chars = len(set(password))
        if unique_chars < len(password):
            repetition_factor = unique_chars / len(password)
            entropy *= repetition_factor
        
        return round(entropy, 2)
    
    def _entropy_to_rating(self, entropy: float) -> str:
        """Convert entropy bits to human-readable rating."""
        if entropy < 28:
            return "Very Weak (easily cracked)"
        elif entropy < 36:
            return "Weak (hours to crack)"
        elif entropy < 60:
            return "Moderate (days to crack)"
        elif entropy < 80:
            return "Strong (years to crack)"
        else:
            return "Very Strong (centuries to crack)"
    
    # ============ Pattern Detection (Sliding Window) ============
    
    def _detect_patterns_sliding_window(self, password: str) -> List[str]:
        """
        Detect common patterns using sliding window algorithm.
        
        Time Complexity: O(n * m) where n = password length, m = pattern count
        
        Patterns detected:
        - Keyboard sequences (qwerty, asdf, etc.)
        - Repeated substrings
        - Sequential numbers/letters
        
        Args:
            password: Password to analyze
            
        Returns:
            List of detected patterns
        """
        patterns = []
        password_lower = password.lower()
        length = len(password)
        
        # === Keyboard Pattern Detection ===
        # Window size: 4 characters minimum
        window_size = 4
        
        for row in self.KEYBOARD_ROWS:
            # Check forward
            for i in range(len(row) - window_size + 1):
                window = row[i:i + window_size]
                if window in password_lower:
                    patterns.append(f"Keyboard: '{window}'")
            
            # Check reverse
            row_reverse = row[::-1]
            for i in range(len(row_reverse) - window_size + 1):
                window = row_reverse[i:i + window_size]
                if window in password_lower:
                    patterns.append(f"Keyboard reverse: '{window}'")
        
        # === Repeated Substring Detection ===
        # Check for repeated patterns of 3+ chars
        for window_size in range(3, min(8, length // 2 + 1)):
            for i in range(length - window_size * 2 + 1):
                window = password_lower[i:i + window_size]
                rest = password_lower[i + window_size:]
                if window in rest:
                    if f"Repeated: '{window}'" not in patterns:
                        patterns.append(f"Repeated: '{window}'")
        
        # === Sequential Characters Detection ===
        # Check for 4+ sequential numbers or letters
        sequential_count = 1
        sequential_type = None
        
        for i in range(1, length):
            curr = ord(password_lower[i])
            prev = ord(password_lower[i-1])
            
            if curr == prev + 1:
                sequential_count += 1
                sequential_type = "ascending"
            elif curr == prev - 1:
                sequential_count += 1
                sequential_type = "descending"
            else:
                if sequential_count >= 4:
                    patterns.append(f"Sequential {sequential_type}: {sequential_count} chars")
                sequential_count = 1
        
        if sequential_count >= 4:
            patterns.append(f"Sequential {sequential_type}: {sequential_count} chars")
        
        return patterns
    
    # ============ Dictionary Detection ============
    
    def _detect_dictionary_words(self, password: str) -> List[str]:
        """
        Detect dictionary words in password.
        
        Uses sliding window with variable sizes.
        
        Args:
            password: Password to check
            
        Returns:
            List of found dictionary words
        """
        found_words = []
        password_lower = password.lower()
        
        # Check each dictionary word
        for word in self.DICTIONARY_WORDS:
            if word in password_lower and len(word) >= 4:
                found_words.append(word)
        
        # Check common passwords
        for word in self.COMMON_PASSWORDS:
            if word in password_lower and word not in found_words:
                found_words.append(word)
        
        return found_words
    
    # ============ Risk Score Calculation ============
    
    def _calculate_risk_score(self, strength_score: int, entropy: float,
                             pattern_count: int, dict_word_count: int,
                             is_expired: bool, is_common: bool) -> float:
        """
        Calculate overall risk score.
        
        Higher score = higher risk (worse password)
        
        Args:
            strength_score: Password strength (0-100)
            entropy: Entropy in bits
            pattern_count: Number of patterns found
            dict_word_count: Number of dictionary words
            is_expired: Whether password is expired
            is_common: Whether it's a common password
            
        Returns:
            Risk score (0-100, higher = worse)
        """
        risk = 0.0
        
        # Inverse of strength (weak = high risk)
        risk += (100 - strength_score) * 0.3
        
        # Low entropy = high risk
        entropy_risk = max(0, (80 - entropy)) * 0.25
        risk += entropy_risk
        
        # Pattern penalties
        risk += pattern_count * 5
        
        # Dictionary word penalties
        risk += dict_word_count * 8
        
        # Expiry penalty
        if is_expired:
            risk += 15
        
        # Common password penalty
        if is_common:
            risk += 25
        
        return min(100, max(0, risk))
    
    # ============ Vault-Wide Analysis ============
    
    def analyze_vault(self, credentials: List[Dict]) -> SecurityReport:
        """
        Analyze all credentials in the vault.
        
        Args:
            credentials: List of credential dicts with password, site_name, etc.
            
        Returns:
            Complete SecurityReport
        """
        self._weak_queue = WeakPasswordQueue()  # Reset queue
        
        analyses: List[PasswordAnalysis] = []
        strength_dist = defaultdict(int)
        age_dist = {'Fresh (< 30 days)': 0, 'Normal (30-90 days)': 0,
                   'Old (90-180 days)': 0, 'Expired (> 180 days)': 0}
        
        total_strength = 0
        total_entropy = 0
        
        # Hash map for reuse detection
        password_hashes: Dict[str, List[str]] = defaultdict(list)
        
        for cred in credentials:
            password = cred.get('password', '')
            if not password:
                continue
            
            analysis = self.analyze_password(
                password=password,
                credential_id=cred.get('id', 0),
                site_name=cred.get('site_name', 'Unknown'),
                username=cred.get('username', 'Unknown'),
                created_at=cred.get('created_at')
            )
            
            analyses.append(analysis)
            
            # Update distributions
            strength_dist[analysis.strength_category] += 1
            total_strength += analysis.strength_score
            total_entropy += analysis.entropy_bits
            
            # Age distribution
            if analysis.password_age_days < 30:
                age_dist['Fresh (< 30 days)'] += 1
            elif analysis.password_age_days < 90:
                age_dist['Normal (30-90 days)'] += 1
            elif analysis.password_age_days < 180:
                age_dist['Old (90-180 days)'] += 1
            else:
                age_dist['Expired (> 180 days)'] += 1
            
            # Add weak passwords to priority queue
            if analysis.strength_score < 60:
                self._weak_queue.push(analysis)
            
            # Track for reuse detection (use first 8 chars of hash)
            pwd_hash = hash(password) & 0xFFFFFFFF  # Simple hash for grouping
            password_hashes[str(pwd_hash)].append(f"{analysis.site_name}:{analysis.username}")
        
        # Find reused passwords
        reused = [(h, sites) for h, sites in password_hashes.items() if len(sites) > 1]
        
        # Calculate overall security score
        count = len(analyses) or 1
        avg_strength = total_strength / count
        avg_entropy = total_entropy / count
        
        # Security score formula
        security_score = self._calculate_vault_security_score(
            avg_strength, avg_entropy, len(reused), 
            len(self._weak_queue), count
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            analyses, reused, avg_strength, avg_entropy
        )
        
        report = SecurityReport(
            timestamp=datetime.now(),
            total_credentials=len(analyses),
            security_score=security_score,
            average_strength=round(avg_strength, 1),
            average_entropy=round(avg_entropy, 1),
            strength_distribution=dict(strength_dist),
            age_distribution=age_dist,
            weak_passwords=self._weak_queue.get_all_sorted(),
            reused_passwords=reused,
            expired_passwords=[a for a in analyses if a.is_expired],
            pattern_passwords=[a for a in analyses if a.patterns_found],
            recommendations=recommendations
        )
        
        self._last_analysis = report
        return report
    
    def _calculate_vault_security_score(self, avg_strength: float, 
                                        avg_entropy: float,
                                        reuse_count: int,
                                        weak_count: int,
                                        total: int) -> float:
        """Calculate overall vault security score."""
        score = 100.0
        
        # Strength contribution (40%)
        score -= (100 - avg_strength) * 0.4
        
        # Entropy contribution (20%)
        entropy_factor = min(1, avg_entropy / 60)
        score -= (1 - entropy_factor) * 20
        
        # Reuse penalty (20%)
        if total > 0:
            reuse_ratio = reuse_count / total
            score -= reuse_ratio * 40
        
        # Weak password penalty (20%)
        if total > 0:
            weak_ratio = weak_count / total
            score -= weak_ratio * 20
        
        return max(0, min(100, score))
    
    def _generate_recommendations(self, analyses: List[PasswordAnalysis],
                                  reused: List[Tuple],
                                  avg_strength: float,
                                  avg_entropy: float) -> List[Dict]:
        """Generate actionable recommendations."""
        recommendations = []
        
        # Critical: Reused passwords
        if reused:
            recommendations.append({
                'priority': 'critical',
                'title': 'Change Reused Passwords Immediately',
                'description': f'Found {len(reused)} groups of credentials sharing the same password. '
                              'If one site is breached, all these accounts are at risk.',
                'category': 'Password Reuse',
                'action': 'Generate unique passwords for each account'
            })
        
        # High: Very weak passwords
        very_weak = [a for a in analyses if a.strength_category in ['Very Weak', 'Weak']]
        if very_weak:
            recommendations.append({
                'priority': 'high',
                'title': f'Strengthen {len(very_weak)} Weak Passwords',
                'description': 'These passwords can be cracked in seconds to minutes. '
                              'Use the password generator for strong, random passwords.',
                'category': 'Password Strength',
                'action': 'Replace with 16+ character passwords using all character types'
            })
        
        # High: Common passwords
        common = [a for a in analyses if 'common password' in str(a.issues).lower()]
        if common:
            recommendations.append({
                'priority': 'high',
                'title': 'Replace Common Passwords',
                'description': 'These passwords appear in breach dictionaries and are tried first by attackers.',
                'category': 'Common Passwords',
                'action': 'Generate random passwords that are not based on words'
            })
        
        # Medium: Low entropy
        low_entropy = [a for a in analyses if a.entropy_bits < 40]
        if low_entropy:
            recommendations.append({
                'priority': 'medium',
                'title': f'{len(low_entropy)} Passwords Have Low Entropy',
                'description': 'These passwords are mathematically predictable. '
                              'Higher entropy means more randomness and security.',
                'category': 'Entropy',
                'action': 'Use longer passwords with mixed character types'
            })
        
        # Medium: Pattern passwords
        pattern_passwords = [a for a in analyses if a.patterns_found]
        if pattern_passwords:
            recommendations.append({
                'priority': 'medium',
                'title': 'Avoid Keyboard Patterns',
                'description': f'{len(pattern_passwords)} passwords contain keyboard patterns '
                              '(qwerty, 123456, etc.) which are easily guessed.',
                'category': 'Patterns',
                'action': 'Remove sequential or keyboard patterns'
            })
        
        # Medium: Expired passwords
        expired = [a for a in analyses if a.is_expired]
        if expired:
            recommendations.append({
                'priority': 'medium',
                'title': f'{len(expired)} Passwords Are Expired',
                'description': 'Industry best practice is to change passwords every 90-180 days.',
                'category': 'Password Age',
                'action': 'Rotate these passwords with new unique ones'
            })
        
        # Low: Enable 2FA
        if analyses:
            recommendations.append({
                'priority': 'low',
                'title': 'Enable Two-Factor Authentication',
                'description': 'Where available, enable 2FA for an additional security layer.',
                'category': 'Account Security',
                'action': 'Enable 2FA on all supported accounts'
            })
        
        return recommendations
    
    # ============ Getters ============
    
    def get_weak_password_queue(self) -> WeakPasswordQueue:
        """Get the priority queue of weak passwords."""
        return self._weak_queue
    
    def get_last_report(self) -> Optional[SecurityReport]:
        """Get the most recent security report."""
        return self._last_analysis


# Singleton instance
_analyzer_instance: Optional[SecurityAnalyzer] = None


def get_security_analyzer() -> SecurityAnalyzer:
    """Get the singleton security analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = SecurityAnalyzer()
    return _analyzer_instance
