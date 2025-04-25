FROM nginx:1.26.3
ADD sources.list /etc/apt/sources.list
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    echo "0 23 * * 6 /usr/sbin/logrotate -v /etc/logrotate.conf" >> /etc/crontab && \
    apt update && \
    apt install logrotate -y
