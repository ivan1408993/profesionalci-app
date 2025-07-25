"""Initial migration

Revision ID: 5165ed538314
Revises: 
Create Date: 2025-07-13 16:36:24.734648

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5165ed538314'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('driver', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('driver_jmbg_hashed_key'), type_='unique')
        batch_op.create_index(batch_op.f('ix_driver_jmbg_hashed'), ['jmbg_hashed'], unique=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('driver', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_driver_jmbg_hashed'))
        batch_op.create_unique_constraint(batch_op.f('driver_jmbg_hashed_key'), ['jmbg_hashed'], postgresql_nulls_not_distinct=False)

    # ### end Alembic commands ###
