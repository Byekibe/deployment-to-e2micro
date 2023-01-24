"""Changed Column password to password_hash

Revision ID: 03666958086e
Revises: dd8859188db8
Create Date: 2023-01-12 16:36:23.879189

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '03666958086e'
down_revision = 'dd8859188db8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('password_hash', sa.String(length=128), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('password_hash')

    # ### end Alembic commands ###