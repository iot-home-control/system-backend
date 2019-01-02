import sqlalchemy
import sqlalchemy.orm
import config
_db_engine = sqlalchemy.create_engine(config.SQLALCHEMY_DATABASE_URI, pool_pre_ping=True)
db_session_factory = sqlalchemy.orm.sessionmaker(bind=_db_engine)
