FROM alpine:3.21.3
EXPOSE 9000
ADD repositories /etc/apk/repositories
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone && \
    apk update && \
    apk add logrotate

COPY app.ini /etc/nginx-ui/app.ini
COPY nginx-ui-2.0.0-rc.5 /usr/bin/nginx-ui
CMD ["nginx-ui", "-config", "/etc/nginx-ui/app.ini"]
