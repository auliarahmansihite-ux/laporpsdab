FROM node:20-alpine

# Set direktori kerja di dalam container
WORKDIR /app

# Copy file package.json dan package-lock.json (jika ada)
COPY package*.json ./

# Install dependencies (hanya production)
RUN npm install --omit=dev

# Copy seluruh source code
COPY . .

# Buat folder uploads jika belum ada
RUN mkdir -p uploads && chown -R node:node uploads

# Expose port aplikasi
EXPOSE 3000

# Jalankan aplikasi
CMD ["npm", "start"]
