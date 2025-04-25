FROM jenkins/inbound-agent:latest-jdk17
ADD make/kubectl /usr/bin/kubectl
ADD make/apache-maven-3.9.9 /usr/local/maven
ENV MAVEN_HOME=/usr/local/maven
ENV PATH=$JAVA_HOME/bin:$MAVEN_HOME/bin:$PATH
ENV TZ=Asia/Shanghai
USER root
RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo "${TZ}" > /etc/timezone
USER jenkins
