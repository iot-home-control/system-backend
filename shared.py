import sqlalchemy
import config
db_engine = sqlalchemy.create_engine(config.SQLALCHEMY_DATABASE_URI)
