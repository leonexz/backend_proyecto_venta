FROM node:22-alpine
WORKDIR /app
COPY backend_proyecto_venta-main/ ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p /uploads && chmod 777 /uploads
EXPOSE 3000
CMD ["npm", "start"]
