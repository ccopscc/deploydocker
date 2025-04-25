FROM ccr.ccs.tencentyun.com/ccops/all:mysql-8
ADD /data/server/nacos/nacos-mysql/mysql-builed/mysql-schema.sql /docker-entrypoint-initdb.d/nacos-mysql.sql
RUN chown -R mysql:mysql /docker-entrypoint-initdb.d/nacos-mysql.sql
EXPOSE 3306
CMD ["mysqld", "--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci"]
