"""Create user and recipe models

Revision ID: 39195c617fd7
Revises: 
Create Date: 2024-10-14 12:15:27.959045

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '39195c617fd7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('_password_hash', sa.String(), nullable=True),
    sa.Column('image_url', sa.String(), nullable=True),
    sa.Column('bio', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('recipes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=False),
    sa.Column('instructions', sa.String(), nullable=False),
    sa.Column('minutes_to_complete', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.CheckConstraint('length(instructions) >= 50', name='check_instructions_length'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], name=op.f('fk_recipes_user_id_users')),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('recipes')
    op.drop_table('users')
    # ### end Alembic commands ###
