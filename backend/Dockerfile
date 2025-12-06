# Use official Node.js 20 image
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production=false

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Expose port (Railway will override this with PORT env var)
EXPOSE 3000

# Start the application
CMD ["npm", "run", "start:prod"]
