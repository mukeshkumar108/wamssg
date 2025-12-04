# Single-stage build for simplicity and reliability
FROM node:20-slim

# Install system dependencies including build tools
RUN apt-get update && apt-get install -y \
    chromium \
    libnss3 \
    libfreetype6 \
    libharfbuzz0b \
    ca-certificates \
    fonts-freefont-ttf \
    dumb-init \
    sqlite3 \
    libsqlite3-dev \
    python3 \
    python3-dev \
    python3-setuptools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app user for security
RUN groupadd -g 1001 nodejs && \
    useradd -m -u 1001 -g nodejs whatsapp

# Set working directory
WORKDIR /app

# Copy package files first for better Docker caching
COPY package*.json ./

# Install dependencies (production only to avoid rebuild issues)
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create output directory and set permissions
RUN mkdir -p out && chown -R whatsapp:nodejs out

# Switch to non-root user
USER whatsapp

# Set environment variables
ENV NODE_ENV=production
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
ENV NODE_OPTIONS="--max-old-space-size=768"

# Expose HTTP port
EXPOSE 3000

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Use dumb-init to handle signals properly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Start the application
CMD ["npx", "ts-node", "index.ts"]
