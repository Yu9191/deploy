FROM node:18-alpine

WORKDIR /app

# 复制并安装依赖
COPY package.json ./
RUN npm install --production

# 复制应用文件
COPY server.js ./

# 创建数据目录
RUN mkdir -p /app/data

# 暴露端口（Koyeb 需要）
EXPOSE 3000

# 启动服务
CMD ["node", "server.js"]
