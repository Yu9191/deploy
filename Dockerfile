FROM node:18-alpine

WORKDIR /app

COPY package.json ./
RUN npm install --production

COPY server.js ./

# 数据目录
RUN mkdir -p /app/data
VOLUME /app/data

# 修改输出路径到数据目录
ENV OUTPUT_PATH=/app/data/cookie.json

CMD ["node", "server.js"]
