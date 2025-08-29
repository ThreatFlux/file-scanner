#!/bin/bash
# Aggressive disk cleanup script for CI environments
# This script removes unnecessary files to maximize available disk space

set -e

echo "🧹 Starting aggressive disk cleanup for CI environment..."
echo "📊 Initial disk usage:"
df -h

# Function to show disk savings
show_savings() {
    local before=$1
    local after=$(df / | tail -1 | awk '{print $4}')
    local saved=$((after - before))
    if [ $saved -gt 0 ]; then
        echo "  ✅ Freed up $(numfmt --to=iec $((saved * 1024))) of disk space"
    fi
}

# Remove Android SDK (saves ~10GB)
if [ -d "/usr/local/lib/android" ]; then
    echo "🗑️  Removing Android SDK..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/local/lib/android
    show_savings $before
fi

# Remove .NET (saves ~2GB)
if [ -d "/usr/share/dotnet" ]; then
    echo "🗑️  Removing .NET..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/share/dotnet
    show_savings $before
fi

# Remove Haskell (saves ~2GB)
if [ -d "/opt/ghc" ] || [ -d "/usr/local/.ghcup" ]; then
    echo "🗑️  Removing Haskell..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /opt/ghc
    sudo rm -rf /usr/local/.ghcup
    show_savings $before
fi

# Remove CodeQL (saves ~5GB)
if [ -d "/opt/hostedtoolcache/CodeQL" ]; then
    echo "🗑️  Removing CodeQL..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /opt/hostedtoolcache/CodeQL
    show_savings $before
fi

# Remove Swift (saves ~1.5GB)
if [ -d "/usr/share/swift" ]; then
    echo "🗑️  Removing Swift..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/share/swift
    show_savings $before
fi

# Remove Julia (saves ~500MB)
if ls /usr/local/julia* 1> /dev/null 2>&1; then
    echo "🗑️  Removing Julia..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/local/julia*
    show_savings $before
fi

# Remove Go (saves ~400MB)
if [ -d "/usr/local/go" ]; then
    echo "🗑️  Removing Go..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/local/go
    show_savings $before
fi

# Remove Kotlin (saves ~300MB)
if [ -d "/usr/share/kotlinc" ]; then
    echo "🗑️  Removing Kotlin..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/share/kotlinc
    show_savings $before
fi

# Remove Miniconda (saves ~500MB)
if [ -d "/usr/share/miniconda" ]; then
    echo "🗑️  Removing Miniconda..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /usr/share/miniconda
    show_savings $before
fi

# Remove build tools we don't need
echo "🗑️  Removing unnecessary build tools..."
before=$(df / | tail -1 | awk '{print $4}')
sudo rm -rf /usr/share/gradle-*
sudo rm -rf /usr/share/apache-maven-*
sudo rm -rf /usr/share/sbt
sudo rm -rf /opt/az
sudo rm -rf /usr/share/az_*
sudo rm -rf /opt/microsoft
sudo rm -rf /opt/google
sudo rm -rf /opt/pipx
sudo rm -rf /usr/local/lib/node_modules
show_savings $before

# Remove unnecessary packages (saves ~2GB)
echo "🗑️  Removing unnecessary packages..."
before=$(df / | tail -1 | awk '{print $4}')
sudo apt-get remove -y \
    '^aspnetcore-.*' \
    '^dotnet-.*' \
    '^llvm-.*' \
    'php.*' \
    '^mongodb-.*' \
    '^mysql-.*' \
    'azure-cli' \
    'google-chrome-stable' \
    'firefox' \
    'powershell' \
    'mono-devel' \
    'libgl1-mesa-dri' \
    '^google-cloud-.*' \
    2>/dev/null || true

sudo apt-get autoremove -y 2>/dev/null || true
sudo apt-get clean
show_savings $before

# Clean Docker if available (saves variable amount)
if command -v docker &> /dev/null; then
    echo "🗑️  Cleaning Docker..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo docker system prune -af --volumes 2>/dev/null || true
    show_savings $before
fi

# Clean snap cache
if [ -d "/var/lib/snapd/cache" ]; then
    echo "🗑️  Cleaning snap cache..."
    before=$(df / | tail -1 | awk '{print $4}')
    sudo rm -rf /var/lib/snapd/cache/*
    show_savings $before
fi

# Clean package manager caches
echo "🗑️  Cleaning package caches..."
before=$(df / | tail -1 | awk '{print $4}')
sudo rm -rf /var/cache/apt/archives/*
sudo rm -rf /var/lib/apt/lists/*
sudo rm -rf /tmp/*
show_savings $before

echo "📊 Final disk usage:"
df -h

echo "✅ Disk cleanup completed!"