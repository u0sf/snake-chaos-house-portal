#!/bin/bash

# Create necessary directories
mkdir -p data

# Copy database and Excel files to data directory
cp club_database.db data/
cp dataleaders_data.xlsx data/
cp requests_history.xlsx data/
cp "SnakeChaosHouse Members.xlsx" data/

# Set permissions
chmod 644 data/* 