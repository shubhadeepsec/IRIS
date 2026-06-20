# IRIS Architecture

IRIS is designed to be highly modular and easily extensible.

## Core Components

1. **CLI / TUI Interfaces**:
   - `cli.py`: Typer-based interface for quick, scriptable profiling.
   - `tui.py`: Textual-based interactive interface with real-time updates and neon-cyan styling.

2. **Collectors**:
   - Reside in `iris/collectors/`.
   - Inherit from `BaseCollector`.
   - Execute the core logic of querying various targets (Domain, Email, Network, Code) and gathering related data.

3. **API Clients**:
   - Found in `iris/api_clients/`.
   - Encapsulate logic for third-party services like GitHub, HIBP, crt.sh.
   - Designed to handle timeouts, rate-limits, and failures gracefully.

4. **Database & Cache**:
   - Defined in `iris/db/`.
   - Utilizes SQLAlchemy to map raw OSINT data into relational schemas (`Domain`, `Email`, `Correlation`).
   - `cache.py` provides an abstraction layer to avoid re-querying expensive or rate-limited endpoints.

5. **Correlation Engine**:
   - Resides in `iris/correlation/`.
   - Analyzes collected data to identify links (e.g. associating an IP address to a Domain).

6. **Exporters**:
   - Available in `iris/exporters/`.
   - Generates JSON, CSV, or formatted HTML reports based on the combined output of the collectors and correlation engine.
