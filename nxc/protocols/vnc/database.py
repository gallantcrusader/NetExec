import warnings

from sqlalchemy import Column, Integer, PrimaryKeyConstraint, String, insert, select
from sqlalchemy.exc import SAWarning
from sqlalchemy.orm import declarative_base

from nxc.database import BaseDB

# if there is an issue with SQLAlchemy and a connection cannot be cleaned up properly it spews out annoying warnings
warnings.filterwarnings("ignore", category=SAWarning)

Base = declarative_base()


class database(BaseDB):
    def __init__(self, db_engine):
        self.HostsTable = None
        self.CredentialsTable = None

        super().__init__(db_engine)

    class Credential(Base):
        __tablename__ = "credentials"
        id = Column(Integer)
        username = Column(String)
        password = Column(String)
        pkey = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    class Host(Base):
        __tablename__ = "hosts"
        id = Column(Integer)
        ip = Column(String)
        hostname = Column(String)
        port = Column(Integer)
        server_banner = Column(String)

        __table_args__ = (
            PrimaryKeyConstraint("id"),
        )

    @staticmethod
    def db_schema(db_conn):
        Base.metadata.create_all(db_conn)

    def reflect_tables(self):
        self.HostsTable = self.reflect_table(self.Host)
        self.CredentialsTable = self.reflect_table(self.Credential)

    def add_credential(self, username, password):
        """Store a successful VNC password login once."""
        q = select(self.CredentialsTable).filter(
            self.CredentialsTable.c.username == username,
            self.CredentialsTable.c.password == password,
        )
        row = self.db_execute(q).first()
        if row is not None:
            return row.id
        result = self.db_execute(insert(self.CredentialsTable).values(username=username, password=password))
        return result.inserted_primary_key[0]

    def get_credentials(self, filter_term=None):
        """Return credentials by ID, username, or all rows."""
        q = select(self.CredentialsTable)
        if isinstance(filter_term, int):
            q = q.filter(self.CredentialsTable.c.id == filter_term)
        elif filter_term:
            q = q.filter(self.CredentialsTable.c.username == filter_term)
        return self.db_execute(q).all()
