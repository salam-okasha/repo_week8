from sqlalchemy import Table, Column, Integer, String, Text, DateTime, ForeignKey, MetaData
from sqlalchemy.sql import func

metadata = MetaData()

logs = Table(
    "logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime, server_default=func.now(), index=True),
    Column("source_ip", String(45), index=True),
    Column("destination_ip", String(45)),
    Column("event_type", String(50)),
    Column("severity", String(20)),
    Column("raw_message", Text),
    Column("created_at", DateTime, server_default=func.now())
)

threat_alerts = Table(
    "threat_alerts",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("log_id", Integer, ForeignKey("logs.id"), nullable=False),
    Column("threat_type", String(100)),
    Column("threat_score", Integer),
    Column("description", Text),
    Column("status", String(20), server_default="unresolved"),
    Column("created_at", DateTime, server_default=func.now())
)