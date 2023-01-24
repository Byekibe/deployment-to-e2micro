"""Initial migration after moving old migrations and initializing another

Revision ID: 35da2b64584e
Revises: 
Create Date: 2023-01-20 14:09:32.669074

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '35da2b64584e'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('verifier', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password', sa.String(length=255), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('verifier', schema=None) as batch_op:
        batch_op.drop_column('password')

    # ### end Alembic commands ###
