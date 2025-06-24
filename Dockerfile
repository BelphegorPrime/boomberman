FROM node:22-alpine

WORKDIR /app

RUN mkdir -p /app/data

VOLUME ["/app/data"]

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

EXPOSE 3000
CMD ["node", "dist/start.js"]
