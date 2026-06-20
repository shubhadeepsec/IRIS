import os
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from iris.db.models import Base, Domain, Email, Correlation, NetworkIP

DB_PATH = os.environ.get("IRIS_DB_PATH", "iris.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Setup engine with SQLite threading settings
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db() -> None:
    """Initialize database and create tables if not existing."""
    Base.metadata.create_all(bind=engine)

def get_session() -> Session:
    """Return a new database session."""
    return SessionLocal()

def is_cached_still_valid(updated_at: Optional[datetime], max_age_hours: int = 24) -> bool:
    """Check if cache record has expired."""
    if not updated_at:
        return False
    return datetime.utcnow() - updated_at < timedelta(hours=max_age_hours)

def get_cached_domain(domain_name: str, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
    """Retrieve domain from cache if valid."""
    session = get_session()
    try:
        domain_name = domain_name.strip().lower()
        record = session.query(Domain).filter(Domain.domain == domain_name).first()
        if record and is_cached_still_valid(record.updated_at, max_age_hours):
            return {
                "id": record.id,
                "domain": record.domain,
                "whois_data": record.whois_data,
                "dns_records": record.dns_records,
                "subdomains": record.subdomains,
                "ssl_cert": record.ssl_cert,
                "created_at": record.created_at,
                "updated_at": record.updated_at
            }
        return None
    finally:
        session.close()

def save_domain(
    domain_name: str,
    whois_data: Dict[str, Any],
    dns_records: Dict[str, Any],
    subdomains: List[str],
    ssl_cert: Optional[Dict[str, Any]] = None
) -> int:
    """Save or update a domain record in cache."""
    session = get_session()
    try:
        domain_name = domain_name.strip().lower()
        record = session.query(Domain).filter(Domain.domain == domain_name).first()
        if not record:
            record = Domain(domain=domain_name)
            session.add(record)
        
        record.whois_data = whois_data
        record.dns_records = dns_records
        record.subdomains = subdomains
        if ssl_cert is not None:
            record.ssl_cert = ssl_cert
        record.updated_at = datetime.utcnow()
        session.commit()
        session.refresh(record)
        return record.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_cached_email(email_address: str, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
    """Retrieve email from cache if valid."""
    session = get_session()
    try:
        email_address = email_address.strip().lower()
        record = session.query(Email).filter(Email.email == email_address).first()
        # Emails don't have updated_at, check created_at
        if record and is_cached_still_valid(record.created_at, max_age_hours):
            return {
                "id": record.id,
                "email": record.email,
                "domain_id": record.domain_id,
                "breached": record.breached,
                "sources": record.sources,
                "created_at": record.created_at
            }
        return None
    finally:
        session.close()

def save_email(
    email_address: str,
    breached: bool,
    sources: List[str],
    domain_id: Optional[int] = None
) -> int:
    """Save or update an email record in cache."""
    session = get_session()
    try:
        email_address = email_address.strip().lower()
        record = session.query(Email).filter(Email.email == email_address).first()
        if not record:
            record = Email(email=email_address)
            session.add(record)
        
        record.breached = breached
        record.sources = list(set(record.sources + sources))
        if domain_id:
            record.domain_id = domain_id
        record.created_at = datetime.utcnow()  # Refresh creation time to extend cache
        session.commit()
        session.refresh(record)
        return record.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_cached_ip(target: str, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
    """Retrieve IP/network data from cache if valid."""
    session = get_session()
    try:
        target = target.strip()
        record = session.query(NetworkIP).filter(NetworkIP.target == target).first()
        if record and is_cached_still_valid(record.updated_at, max_age_hours):
            return {
                "id": record.id,
                "target": record.target,
                "ip_address": record.ip_address,
                "geo": record.geo_data,
                "shodan": getattr(record, "shodan_data", {}),
                "created_at": record.created_at,
                "updated_at": record.updated_at
            }
        return None
    finally:
        session.close()

def save_ip(
    target: str,
    ip_address: str,
    geo_data: Dict[str, Any],
    shodan_data: Optional[Dict[str, Any]] = None
) -> int:
    """Save or update an IP record in cache."""
    session = get_session()
    try:
        target = target.strip()
        record = session.query(NetworkIP).filter(NetworkIP.target == target).first()
        if not record:
            record = NetworkIP(target=target, ip_address=ip_address)
            session.add(record)
        
        record.ip_address = ip_address
        record.geo_data = geo_data
        if shodan_data is not None:
            record.shodan_data = shodan_data
        record.updated_at = datetime.utcnow()
        session.commit()
        session.refresh(record)
        return record.id
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def save_correlation(
    entity_a: str,
    entity_b: str,
    relationship_type: str,
    confidence: float = 1.0
) -> None:
    """Save correlation between entities."""
    session = get_session()
    try:
        entity_a = entity_a.strip()
        entity_b = entity_b.strip()
        # Deduplicate so entity_a -> entity_b relationship is unique
        record = session.query(Correlation).filter(
            Correlation.entity_a == entity_a,
            Correlation.entity_b == entity_b,
            Correlation.relationship == relationship_type
        ).first()
        if not record:
            record = Correlation(
                entity_a=entity_a,
                entity_b=entity_b,
                relationship=relationship_type,
                confidence=confidence
            )
            session.add(record)
        else:
            record.confidence = confidence
            record.created_at = datetime.utcnow()
        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

def get_correlations(entity: str) -> List[Dict[str, Any]]:
    """Retrieve all correlations related to an entity."""
    session = get_session()
    try:
        entity = entity.strip()
        # Find where entity is either entity_a or entity_b
        records = session.query(Correlation).filter(
            (Correlation.entity_a == entity) | (Correlation.entity_b == entity)
        ).all()
        return [
            {
                "entity_a": r.entity_a,
                "entity_b": r.entity_b,
                "relationship": r.relationship,
                "confidence": r.confidence,
                "created_at": r.created_at
            }
            for r in records
        ]
    finally:
        session.close()
