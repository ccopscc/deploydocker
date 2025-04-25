FROM node:22-alpine
RUN npm config set registry http://registry.npm.taobao.org/ && \
npm install -g npm && \
npm install -g hexo && \
mkdir /opt/blog && \
cd /opt/blog && \
hexo i

COPY source_data/ /opt/blog/
RUN npm install npm-check-updates --prefix /opt/blog/
WORKDIR /opt/blog/
CMD ["hexo", "server"]
