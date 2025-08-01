"""Dodato polje phone_number u Employer

Revision ID: c1b3a4604400
Revises: 5165ed538314
Create Date: 2025-07-24 22:05:54.514358

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1b3a4604400'
down_revision = '5165ed538314'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('employer', schema=None) as batch_op:
        batch_op.add_column(sa.Column('phone_number', sa.String(length=20), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('employer', schema=None) as batch_op:
        batch_op.drop_column('phone_number')

    # ### end Alembic commands ###
