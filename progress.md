V1 completed. Built a simple CLI tool as the foundation of this too. 
Structure:
Input URL
    ↓
IP check        ← net.ParseIP, handles IPv4 + IPv6 + ports
Keyword check   ← local, offline
Length check    ← local, offline
    ↓
Output


V2 completed. Upgraded and added an API function.
Structure:
Input URL
    ↓
IP check        ← net.ParseIP, handles IPv4 + IPv6 + ports
Keyword check   ← local, offline
Length check    ← local, offline
    ↓
VirusTotal      ← real API, 70+ engines, graceful failure if offline
    ↓
Output