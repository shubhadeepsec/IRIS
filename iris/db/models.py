from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, JSON
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class Domain(Base):
    __tablename__ = "domains"
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True, nullable=False)
    whois_data = Column(JSON, default=dict)
    dns_records = Column(JSON, default=dict)
    subdomains = Column(JSON, default=list)
    ssl_cert = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    emails = relationship("Email", back_populates="domain", cascade="all, delete-orphan")

class Email(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    domain_id = Column(Integer, ForeignKey("domains.id"), nullable=True)
    breached = Column(Boolean, default=False)
    sources = Column(JSON, default=list)  # Where found (e.g., website, github, pgp)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    domain = relationship("Domain", back_populates="emails")

class Correlation(Base):
    __tablename__ = "correlations"
    id = Column(Integer, primary_key=True)
    entity_a = Column(String, nullable=False)  # email, domain, IP, username
    entity_b = Column(String, nullable=False)
    relationship = Column(String, nullable=False)  # "shared_email", "same_ip", "username_reuse", "associated_domain"
    confidence = Column(Float, default=1.0)  # 0.0-1.0
    created_at = Column(DateTime, default=datetime.utcnow)
