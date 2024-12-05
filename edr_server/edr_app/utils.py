from .models import Process, Port, Vulnerability, VulnerabilityMatch
from django.utils import timezone
import re

def analyze_vulnerabilities(client):
    """
    Analyze processes and ports for potential vulnerabilities.
    Returns a list of VulnerabilityMatch objects.
    """
    # Clear previous matches for this client
    VulnerabilityMatch.objects.filter(client=client).delete()
    matches = []

    # Get all active processes and ports for the client
    processes = Process.objects.filter(client=client)
    ports = Port.objects.filter(client=client)
    vulnerabilities = Vulnerability.objects.all()

    # Analyze processes
    for process in processes:
        for vuln in vulnerabilities:
            # Check if process name matches affected software
            if _match_software(process.name, vuln.affected_software):
                # Check version if available
                confidence = _calculate_confidence(process, vuln)
                if confidence > 0:
                    match = VulnerabilityMatch.objects.create(
                        vulnerability=vuln,
                        client=client,
                        match_type='PROCESS',
                        process=process,
                        confidence_score=confidence
                    )
                    matches.append(match)

    # Analyze ports and services
    for port in ports:
        for vuln in vulnerabilities:
            # Check if service name matches affected software
            if port.service_name and _match_software(port.service_name, vuln.affected_software):
                confidence = _calculate_service_confidence(port, vuln)
                if confidence > 0:
                    match = VulnerabilityMatch.objects.create(
                        vulnerability=vuln,
                        client=client,
                        match_type='SERVICE',
                        port=port,
                        confidence_score=confidence
                    )
                    matches.append(match)

            # Check common vulnerable ports
            if _is_vulnerable_port(port.port_number, vuln):
                match = VulnerabilityMatch.objects.create(
                    vulnerability=vuln,
                    client=client,
                    match_type='PORT',
                    port=port,
                    confidence_score=0.5  # Base confidence for port matches
                )
                matches.append(match)

    return matches

def _match_software(name, affected_software):
    """Check if software name matches affected software pattern."""
    if not name or not affected_software:
        return False
    
    # Convert both to lowercase for case-insensitive matching
    name = name.lower()
    affected_software = affected_software.lower()
    
    # Split affected_software by common separators
    patterns = affected_software.replace(',', ' ').split()
    
    for pattern in patterns:
        if pattern in name:
            return True
    
    return False

def _calculate_confidence(process, vulnerability):
    """Calculate confidence score for process vulnerability match."""
    confidence = 0.0
    
    # Base confidence if software name matches
    if _match_software(process.name, vulnerability.affected_software):
        confidence = 0.5
        
        # Additional confidence if version matches
        if process.version and vulnerability.affected_versions:
            if _version_matches(process.version, vulnerability.affected_versions):
                confidence += 0.5
    
    return confidence

def _calculate_service_confidence(port, vulnerability):
    """Calculate confidence score for service vulnerability match."""
    confidence = 0.0
    
    # Base confidence if service name matches
    if port.service_name and _match_software(port.service_name, vulnerability.affected_software):
        confidence = 0.5
        
        # Additional confidence if version matches
        if port.service_version and vulnerability.affected_versions:
            if _version_matches(port.service_version, vulnerability.affected_versions):
                confidence += 0.5
    
    return confidence

def _version_matches(version, affected_versions):
    """Check if version matches affected versions pattern."""
    if not version or not affected_versions:
        return False
    
    # Convert version strings to comparable format
    version = version.lower()
    affected_versions = affected_versions.lower()
    
    # Handle various version patterns (e.g., "<=2.0.0", "2.x", "1.0-2.0")
    version_patterns = affected_versions.split(',')
    
    for pattern in version_patterns:
        pattern = pattern.strip()
        
        # Handle range pattern (e.g., "1.0-2.0")
        if '-' in pattern:
            start, end = pattern.split('-')
            if _version_in_range(version, start, end):
                return True
        
        # Handle comparison patterns (e.g., "<=2.0.0")
        elif any(op in pattern for op in ['<=', '>=', '<', '>', '=']):
            op = re.findall(r'(<=|>=|<|>|=)', pattern)[0]
            ver = pattern.replace(op, '').strip()
            if _compare_versions(version, ver, op):
                return True
        
        # Handle exact match or wildcard
        elif pattern == version or (pattern.endswith('.x') and version.startswith(pattern[:-2])):
            return True
    
    return False

def _version_in_range(version, start, end):
    """Check if version is within range."""
    try:
        version_parts = [int(p) for p in version.split('.')]
        start_parts = [int(p) for p in start.split('.')]
        end_parts = [int(p) for p in end.split('.')]
        
        return start_parts <= version_parts <= end_parts
    except (ValueError, AttributeError):
        return False

def _compare_versions(version1, version2, operator):
    """Compare two version strings using the specified operator."""
    try:
        v1_parts = [int(p) for p in version1.split('.')]
        v2_parts = [int(p) for p in version2.split('.')]
        
        # Pad shorter version with zeros
        max_length = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_length - len(v1_parts)))
        v2_parts.extend([0] * (max_length - len(v2_parts)))
        
        if operator == '<=':
            return v1_parts <= v2_parts
        elif operator == '>=':
            return v1_parts >= v2_parts
        elif operator == '<':
            return v1_parts < v2_parts
        elif operator == '>':
            return v1_parts > v2_parts
        elif operator == '=':
            return v1_parts == v2_parts
        
    except (ValueError, AttributeError):
        return False
    
    return False

def _is_vulnerable_port(port_number, vulnerability):
    """Check if port number is commonly associated with vulnerabilities."""
    # Common vulnerable ports and their typical services
    VULNERABLE_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        135: 'RPC',
        139: 'NetBIOS',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-ALT'
    }
    
    if port_number in VULNERABLE_PORTS:
        service = VULNERABLE_PORTS[port_number]
        # Check if vulnerability affects this service
        return _match_software(service, vulnerability.affected_software)
    
    return False
